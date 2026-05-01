#![allow(dead_code)]
//! Minimal fake hub for integration testing.
//!
//! Implements only the RPCs needed for P2P connection establishment:
//! - `GetStunTurnConfig`
//! - `StartServing`
//! - `StartConnection`

use std::collections::HashMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use tokio::sync::{Mutex, mpsc, oneshot};
use tokio_stream::{Stream, StreamExt};
use tonic::{Request, Response, Status, Streaming};

// Use the proto types from the library
use prost::Message;
use wispers_connect::hub::proto::{
    DeregisterNodeRequest, DeregisterNodeResponse, ListNodesRequest, NodeList, NodeRegistration,
    NodeRegistrationRequest, PairNodesMessage, RosterRequest, ServingRequest, ServingResponse,
    StartConnectionRequest, StartConnectionResponse, StunTurnConfig, StunTurnConfigRequest,
    UpdateRosterRequest, UpdateRosterResponse, Welcome,
    hub_server::{Hub, HubServer},
    roster, serving_request, serving_response, start_connection_request,
};

/// A pending connection request waiting for the answerer's response.
struct PendingConnection {
    #[allow(dead_code)]
    request: StartConnectionRequest,
    response_tx: oneshot::Sender<Result<StartConnectionResponse, String>>,
}

/// State shared between the hub service methods.
struct HubState {
    /// Nodes currently serving: `node_number` -> channel to send requests
    serving_nodes: HashMap<i32, mpsc::Sender<ServingRequest>>,

    /// Pending connection requests: `request_id` -> pending connection
    pending_connections: HashMap<i64, PendingConnection>,

    /// Next request ID
    next_request_id: i64,
}

impl HubState {
    fn new() -> Self {
        Self {
            serving_nodes: HashMap::new(),
            pending_connections: HashMap::new(),
            next_request_id: 1,
        }
    }
}

/// Fake hub implementation.
pub struct FakeHub {
    state: Arc<Mutex<HubState>>,
    roster: roster::Roster,
}

impl FakeHub {
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(HubState::new())),
            roster: roster::Roster::default(),
        }
    }

    /// Create a fake hub with a specific roster.
    pub fn with_roster(roster: roster::Roster) -> Self {
        Self {
            state: Arc::new(Mutex::new(HubState::new())),
            roster,
        }
    }

    /// Start the fake hub server and return the address it's listening on.
    pub async fn start(
        self,
    ) -> Result<(SocketAddr, tokio::task::JoinHandle<()>), Box<dyn std::error::Error + Send + Sync>>
    {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;

        let handle = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(HubServer::new(self))
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
                .await
                .expect("running tokio server");
        });

        Ok((addr, handle))
    }
}

#[tonic::async_trait]
impl Hub for FakeHub {
    async fn complete_node_registration(
        &self,
        _request: Request<NodeRegistrationRequest>,
    ) -> Result<Response<NodeRegistration>, Status> {
        Err(Status::unimplemented("not needed for P2P testing"))
    }

    async fn pair_nodes(
        &self,
        _request: Request<PairNodesMessage>,
    ) -> Result<Response<PairNodesMessage>, Status> {
        Err(Status::unimplemented("not needed for P2P testing"))
    }

    async fn update_roster(
        &self,
        _request: Request<UpdateRosterRequest>,
    ) -> Result<Response<UpdateRosterResponse>, Status> {
        Err(Status::unimplemented("not needed for P2P testing"))
    }

    async fn list_nodes(
        &self,
        _request: Request<ListNodesRequest>,
    ) -> Result<Response<NodeList>, Status> {
        Err(Status::unimplemented("not needed for P2P testing"))
    }

    async fn deregister_node(
        &self,
        _request: Request<DeregisterNodeRequest>,
    ) -> Result<Response<DeregisterNodeResponse>, Status> {
        Ok(Response::new(DeregisterNodeResponse {}))
    }

    async fn get_roster(
        &self,
        _request: Request<RosterRequest>,
    ) -> Result<Response<roster::Roster>, Status> {
        Ok(Response::new(self.roster.clone()))
    }

    type StartServingStream =
        Pin<Box<dyn Stream<Item = Result<ServingRequest, Status>> + Send + 'static>>;

    async fn start_serving(
        &self,
        request: Request<Streaming<ServingResponse>>,
    ) -> Result<Response<Self::StartServingStream>, Status> {
        // Extract node number from metadata
        let node_number: i32 = request
            .metadata()
            .get("x-node-number")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| Status::invalid_argument("missing x-node-number"))?;

        // Channel for sending requests to this serving node
        let (request_tx, request_rx) = mpsc::channel::<ServingRequest>(16);

        // Register this node as serving
        {
            let mut state = self.state.lock().await;
            state.serving_nodes.insert(node_number, request_tx);
        }

        // Spawn task to handle responses from the serving node
        let state = self.state.clone();
        let mut response_stream = request.into_inner();
        tokio::spawn(async move {
            while let Some(result) = response_stream.next().await {
                match result {
                    Ok(response) => {
                        let mut state = state.lock().await;
                        if let Some(pending) =
                            state.pending_connections.remove(&response.request_id)
                        {
                            if !response.error.is_empty() {
                                let _ = pending.response_tx.send(Err(response.error));
                            } else if let Some(serving_response::Kind::StartConnectionResponse(
                                conn_resp,
                            )) = response.kind
                            {
                                let _ = pending.response_tx.send(Ok(conn_resp));
                            }
                        }
                    }
                    Err(_) => break,
                }
            }

            // Node disconnected, remove from serving nodes
            let mut state = state.lock().await;
            state.serving_nodes.remove(&node_number);
        });

        // Send welcome message, then forward requests
        let welcome_stream = async_stream::stream! {
            yield Ok(ServingRequest {
                dest_node_number: node_number,
                source_node_number: 0,
                request_id: 0,
                kind: Some(serving_request::Kind::Welcome(Welcome {})),
            });

            let mut rx = request_rx;
            while let Some(req) = rx.recv().await {
                yield Ok(req);
            }
        };

        Ok(Response::new(Box::pin(welcome_stream)))
    }

    async fn get_stun_turn_config(
        &self,
        _request: Request<StunTurnConfigRequest>,
    ) -> Result<Response<StunTurnConfig>, Status> {
        // Return bogus/unreachable STUN server - libjuice will use local candidates only
        Ok(Response::new(StunTurnConfig {
            stun_server: "stun:192.0.2.1:3478".to_string(), // TEST-NET-1, unreachable
            turn_server: String::new(),
            turn_username: String::new(),
            turn_password: String::new(),
            expires_at_millis: 0,
        }))
    }

    async fn start_connection(
        &self,
        request: Request<StartConnectionRequest>,
    ) -> Result<Response<StartConnectionResponse>, Status> {
        // Extract caller's node number from metadata
        let caller_node_number: i32 = request
            .metadata()
            .get("x-node-number")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| Status::invalid_argument("missing x-node-number"))?;

        let conn_request = request.into_inner();

        // Decode the signed payload to get the routing field, just like
        // the real hub would. The raw signed_payload bytes are forwarded
        // unchanged to preserve signature integrity.
        let payload =
            start_connection_request::Payload::decode(conn_request.signed_payload.as_slice())
                .map_err(|_| Status::invalid_argument("cannot decode signed payload"))?;
        let answerer_node_number = payload.answerer_node_number;

        // Find the answerer's serving channel
        let (request_id, request_tx) = {
            let mut state = self.state.lock().await;
            let request_tx = state
                .serving_nodes
                .get(&answerer_node_number)
                .cloned()
                .ok_or_else(|| Status::not_found("answerer not serving"))?;

            let request_id = state.next_request_id;
            state.next_request_id += 1;

            (request_id, request_tx)
        };

        // Create channel for the response
        let (response_tx, response_rx) = oneshot::channel();

        // Register pending connection
        {
            let mut state = self.state.lock().await;
            state.pending_connections.insert(
                request_id,
                PendingConnection {
                    request: conn_request.clone(),
                    response_tx,
                },
            );
        }

        // Forward request to answerer
        let serving_request = ServingRequest {
            dest_node_number: answerer_node_number,
            source_node_number: caller_node_number,
            request_id,
            kind: Some(serving_request::Kind::StartConnectionRequest(conn_request)),
        };

        request_tx
            .send(serving_request)
            .await
            .map_err(|_| Status::unavailable("answerer disconnected"))?;

        // Wait for response
        let response = response_rx
            .await
            .map_err(|_| Status::unavailable("answerer disconnected"))?
            .map_err(Status::aborted)?;

        Ok(Response::new(response))
    }
}
