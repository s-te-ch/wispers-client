//! Integration tests for P2P connections.
//!
//! Tests the full P2P flow using a fake hub for signaling.

mod common;

use std::time::Duration;

use wispers_connect::hub::proto::roster::Roster;
use wispers_connect::{
    AuthToken, ConnectivityGroupId, Node, NodeRegistration, SigningKeyPair,
    add_revocation_to_roster, build_activation_payload, build_revocation_payload,
    compute_signing_hash, create_bootstrap_roster, set_endorser_signature, set_new_node_signature,
    set_revoker_signature,
};

use common::FakeHub;

/// Poll `cond` until it returns true, panicking if it doesn't within 5s.
async fn wait_for(mut cond: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while !cond() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("condition not met within timeout");
}

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
    let hub_url = format!("http://{}", hub_addr);

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

/// A revoked caller must be rejected by the answerer's own roster check, not
/// only by the caller's client-side self-check. Simulated by having the hub
/// serve the caller a stale roster (from before its revocation), so the caller
/// still believes it is active and proceeds, while the answerer verifies the
/// current roster and must refuse the connection.
#[tokio::test]
async fn test_revoked_caller_rejected_by_answerer() {
    let root_key_1 = [41u8; 32];
    let root_key_2 = [42u8; 32];
    let signing_key_1 = SigningKeyPair::derive_from_root_key(&root_key_1);
    let signing_key_2 = SigningKeyPair::derive_from_root_key(&root_key_2);

    // Stale roster: both nodes active. Current roster: node 1 revoked by node 2.
    let stale_roster = create_test_roster(&signing_key_1, 1, &signing_key_2, 2);
    let mut current_roster = stale_roster.clone();
    let payload = build_revocation_payload(&current_roster, 1, 2);
    add_revocation_to_roster(&mut current_roster, payload);
    let signing_hash = compute_signing_hash(&current_roster);
    set_revoker_signature(&mut current_roster, signing_key_2.sign(&signing_hash));

    let hub =
        FakeHub::with_roster(current_roster.clone()).with_roster_for_node(1, stale_roster.clone());
    let (hub_addr, _hub_handle) = hub.start().await.expect("hub starts");
    let hub_url = format!("http://{}", hub_addr);

    let group_id = ConnectivityGroupId::from("test-group");
    let registration_1 =
        NodeRegistration::new(group_id.clone(), 1, AuthToken::new("token1"), String::new());
    let registration_2 =
        NodeRegistration::new(group_id, 2, AuthToken::new("token2"), String::new());

    let node1 =
        Node::new_activated_for_test(root_key_1, stale_roster, registration_1, hub_url.clone());
    let node2 = Node::new_activated_for_test(root_key_2, current_roster, registration_2, hub_url);

    // Node 2 (the answerer) starts serving; it sees the current roster.
    let (handle, session, mut incoming_rx) =
        node2.start_serving().await.expect("node2 starts serving");
    let session_handle = tokio::spawn(async move {
        let _ = session.run().await;
    });
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Node 1 believes it is still active and tries to connect.
    let Err(err) = node1.connect_udp(2).await else {
        panic!("revoked caller must be rejected");
    };
    assert!(
        err.to_string().contains("revoked"),
        "expected a revocation rejection, got: {}",
        err
    );

    // Nothing must have surfaced on the answerer's incoming channel.
    assert!(incoming_rx.udp.try_recv().is_err());

    drop(handle);
    session_handle.abort();
}

/// A hub blip (stream drop) must not stop a long-running serving session: it
/// should reconnect on its own, keep its outstanding activation codes, and
/// report itself disconnected-then-connected rather than silently healthy.
#[tokio::test]
async fn test_serving_reconnects_after_hub_blip() {
    let root_key_1 = [31u8; 32];
    let root_key_2 = [32u8; 32];
    let signing_key_1 = SigningKeyPair::derive_from_root_key(&root_key_1);
    let signing_key_2 = SigningKeyPair::derive_from_root_key(&root_key_2);
    let roster = create_test_roster(&signing_key_1, 1, &signing_key_2, 2);

    let hub = FakeHub::with_roster(roster.clone());
    let ctrl = hub.controller();
    let (hub_addr, _hub_handle) = hub.start().await.expect("hub starts");
    let hub_url = format!("http://{}", hub_addr);

    let registration_2 = NodeRegistration::new(
        ConnectivityGroupId::from("test-reconnect"),
        2,
        AuthToken::new("token2"),
        String::new(),
    );
    let node2 = Node::new_activated_for_test(root_key_2, roster, registration_2, hub_url);

    let (handle, session, _incoming) = node2.start_serving().await.expect("node2 serves");
    let session_task = tokio::spawn(async move {
        let _ = session.run().await;
    });

    // First connection established.
    wait_for(|| ctrl.serve_count() >= 1).await;
    assert!(
        handle.status().await.expect("status").connected,
        "should be connected after start"
    );

    // Generate an activation code that must survive the reconnect.
    handle.generate_activation_code().await.expect("gen code");
    assert_eq!(
        handle
            .status()
            .await
            .expect("status")
            .endorsing
            .map(|e| e.codes_outstanding),
        Some(1),
    );

    // Simulate a hub blip: the current stream ends under the session.
    ctrl.force_disconnect().await;

    // The session reconnects on its own (a second start_serving stream).
    wait_for(|| ctrl.serve_count() >= 2).await;

    // `connected` is set just after the new stream opens; poll briefly for it.
    let mut status = handle.status().await.expect("status");
    for _ in 0..50 {
        if status.connected {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
        status = handle.status().await.expect("status");
    }
    assert!(status.connected, "should be reconnected");
    assert_eq!(
        status.endorsing.map(|e| e.codes_outstanding),
        Some(1),
        "outstanding activation code should survive reconnect",
    );

    handle.shutdown().await.expect("shutdown");
    let _ = session_task.await;
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
    let hub_url = format!("http://{}", hub_addr);

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
        let msg = format!("message {} from caller", i);
        caller.send(msg.as_bytes()).expect("send succeeds");
        let received = answerer.recv().await.expect("recv succeeds");
        assert_eq!(received, msg.as_bytes());

        let msg = format!("message {} from answerer", i);
        answerer.send(msg.as_bytes()).expect("send succeeds");
        let received = caller.recv().await.expect("recv succeeds");
        assert_eq!(received, msg.as_bytes());
    }

    session_handle.abort();
}
