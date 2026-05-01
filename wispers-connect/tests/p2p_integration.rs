//! Integration tests for P2P connections.
//!
//! Tests the full P2P flow using a fake hub for signaling.

mod common;

use wispers_connect::Node;
use wispers_connect::crypto::SigningKeyPair;
use wispers_connect::hub::proto::roster::Roster;
use wispers_connect::roster::{
    build_activation_payload, compute_signing_hash, create_bootstrap_roster,
    set_endorser_signature, set_new_node_signature,
};
use wispers_connect::types::{AuthToken, ConnectivityGroupId, NodeRegistration};

use common::FakeHub;

/// Create a properly signed test roster with two nodes.
fn create_test_roster(
    key1: &SigningKeyPair,
    node1_number: i32,
    key2: &SigningKeyPair,
    node2_number: i32,
) -> Roster {
    // Node 2 is the "new node" being activated, endorsed by node 1.
    let payload = build_activation_payload(
        &Roster::default(),
        node2_number,
        node1_number,
        b"node2_nonce".to_vec(),
        b"node1_nonce".to_vec(),
    );
    let mut roster =
        create_bootstrap_roster(payload, &key2.public_key_spki(), &key1.public_key_spki());
    let signing_hash = compute_signing_hash(&roster);
    set_new_node_signature(&mut roster, key2.sign(&signing_hash));
    set_endorser_signature(&mut roster, key1.sign(&signing_hash));
    roster
}

/// Test that two nodes can connect via the fake hub and exchange messages.
#[tokio::test]
async fn test_p2p_connection_via_hub() {
    // Create two nodes with different root keys
    let root_key_1 = [1u8; 32];
    let root_key_2 = [2u8; 32];

    let signing_key_1 = SigningKeyPair::derive_from_root_key(&root_key_1);
    let signing_key_2 = SigningKeyPair::derive_from_root_key(&root_key_2);

    // Create properly signed roster with both nodes
    let roster = create_test_roster(&signing_key_1, 1, &signing_key_2, 2);

    // Start fake hub with the roster
    let hub = FakeHub::with_roster(roster.clone());
    let (hub_addr, _hub_handle) = hub.start().await.expect("hub starts");
    let hub_url = format!("http://{hub_addr}");

    // Create registrations
    let group_id = ConnectivityGroupId::from("test-group");
    let registration_1 =
        NodeRegistration::new(group_id.clone(), 1, AuthToken::new("token1"), String::new());
    let registration_2 =
        NodeRegistration::new(group_id, 2, AuthToken::new("token2"), String::new());

    // Create activated nodes
    let node1 =
        Node::new_activated_for_test(root_key_1, roster.clone(), registration_1, hub_url.clone());
    let node2 = Node::new_activated_for_test(root_key_2, roster, registration_2, hub_url);

    // Node 2 starts serving
    let (handle, session, mut incoming_rx) =
        node2.start_serving().await.expect("node2 starts serving");

    // Run the serving session in background
    let session_handle = tokio::spawn(async move {
        let _ = session.run().await;
    });

    // Give the serving session time to connect
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Node 1 connects to node 2
    let caller_conn = node1.connect_udp(2).await.expect("node1 connects to node2");

    // Node 2 receives the incoming connection (on UDP channel, already connected)
    let answerer_conn = incoming_rx
        .udp
        .recv()
        .await
        .expect("node2 receives connection")
        .expect("connection handshake succeeds");

    // Exchange messages
    caller_conn
        .send(b"hello from node 1")
        .expect("caller sends");
    let received = answerer_conn.recv().await.expect("answerer receives");
    assert_eq!(received, b"hello from node 1");

    answerer_conn
        .send(b"hello from node 2")
        .expect("answerer sends");
    let received = caller_conn.recv().await.expect("caller receives");
    assert_eq!(received, b"hello from node 2");

    // Clean up
    drop(handle);
    session_handle.abort();
}

/// Test multiple messages in both directions.
#[tokio::test]
async fn test_p2p_multiple_messages() {
    let root_key_1 = [10u8; 32];
    let root_key_2 = [20u8; 32];

    let signing_key_1 = SigningKeyPair::derive_from_root_key(&root_key_1);
    let signing_key_2 = SigningKeyPair::derive_from_root_key(&root_key_2);

    let roster = create_test_roster(&signing_key_1, 1, &signing_key_2, 2);

    let hub = FakeHub::with_roster(roster.clone());
    let (hub_addr, _hub_handle) = hub.start().await.expect("hub starts");
    let hub_url = format!("http://{hub_addr}");

    let group_id = ConnectivityGroupId::from("test");
    let node1 = Node::new_activated_for_test(
        root_key_1,
        roster.clone(),
        NodeRegistration::new(group_id.clone(), 1, AuthToken::new("t1"), String::new()),
        hub_url.clone(),
    );
    let node2 = Node::new_activated_for_test(
        root_key_2,
        roster,
        NodeRegistration::new(group_id, 2, AuthToken::new("t2"), String::new()),
        hub_url,
    );

    let (_handle, session, mut incoming_rx) = node2.start_serving().await.expect("serving starts");
    let session_handle = tokio::spawn(async move {
        let _ = session.run().await;
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let caller = node1.connect_udp(2).await.expect("connects");
    let answerer = incoming_rx
        .udp
        .recv()
        .await
        .expect("receives connection")
        .expect("connection handshake succeeds");

    // Send 10 messages each way
    for i in 0..10 {
        let msg = format!("message {i} from caller");
        caller.send(msg.as_bytes()).expect("send succeeds");
        let received = answerer.recv().await.expect("recv succeeds");
        assert_eq!(received, msg.as_bytes());

        let msg = format!("message {i} from answerer");
        answerer.send(msg.as_bytes()).expect("send succeeds");
        let received = caller.recv().await.expect("recv succeeds");
        assert_eq!(received, msg.as_bytes());
    }

    session_handle.abort();
}
