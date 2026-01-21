//! Roster verification for Wispers Connect.
//!
//! This module provides cryptographic verification of the roster, ensuring the
//! chain of trust from version 1 to the current version is valid.

use crate::hub::proto::connect::roster::{self, addendum, Roster};
use ed25519_dalek::pkcs8::DecodePublicKey;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use prost::Message;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// Get active (non-revoked) nodes from a roster.
pub fn active_nodes(roster: &Roster) -> impl Iterator<Item = &roster::Node> {
    roster.nodes.iter().filter(|n| !n.revoked)
}

/// Errors that can occur during roster verification.
#[derive(Debug, thiserror::Error)]
pub enum RosterVerificationError {
    #[error("roster version must be >= 1, got {0}")]
    InvalidVersion(i64),

    #[error("expected {expected} nodes for version {version}, got {actual}")]
    NodeCountMismatch {
        version: i64,
        expected: usize,
        actual: usize,
    },

    #[error("expected {expected} addenda for version {version}, got {actual}")]
    AddendaCountMismatch {
        version: i64,
        expected: usize,
        actual: usize,
    },

    #[error("duplicate node number: {0}")]
    DuplicateNode(i32),

    #[error("failed to decode public key for node {node_number}: {reason}")]
    InvalidPublicKey { node_number: i32, reason: String },

    #[error("verifier node {0} not found in roster")]
    VerifierNotInRoster(i32),

    #[error("verifier node {0} has been revoked")]
    VerifierRevoked(i32),

    #[error("verifier public key mismatch for node {0}")]
    VerifierKeyMismatch(i32),

    #[error("addendum at index {0} is missing")]
    MissingAddendum(usize),

    #[error("addendum at index {0} has no kind")]
    EmptyAddendum(usize),

    #[error("activation payload missing at version {0}")]
    MissingActivationPayload(i64),

    #[error("revocation payload missing at version {0}")]
    MissingRevocationPayload(i64),

    #[error("new node signature invalid at version {0}")]
    InvalidNewNodeSignature(i64),

    #[error("endorser signature invalid at version {0}")]
    InvalidEndorserSignature(i64),

    #[error("revoker signature invalid at version {0}")]
    InvalidRevokerSignature(i64),

    #[error("new node {new_node} not found in roster at version {version}")]
    NewNodeNotInRoster { version: i64, new_node: i32 },

    #[error("new node {0} is same as endorser")]
    NewNodeIsEndorser(i32),

    #[error("endorser {endorser} not active in roster before version {version}")]
    EndorserNotInPreviousRoster { version: i64, endorser: i32 },

    #[error("revoker {revoker} not active in roster before version {version}")]
    RevokerNotInPreviousRoster { version: i64, revoker: i32 },

    #[error("revoked node {revoked} not in roster at version {version}")]
    RevokedNodeNotInRoster { version: i64, revoked: i32 },

    #[error("base version hash mismatch at version {0}")]
    BaseHashMismatch(i64),

    #[error("version mismatch in addendum: expected {expected}, got {actual}")]
    VersionMismatch { expected: i64, actual: i64 },
}

/// Verify a roster's cryptographic integrity.
///
/// This verifies the complete chain of trust from version 1 to the current version,
/// checking all signatures and hash chains.
///
/// # Arguments
/// * `roster` - The roster to verify
/// * `verifier_node_number` - The node number of the verifier (must be in roster)
/// * `verifier_public_key_spki` - The verifier's expected public key in SPKI DER format
///
/// # Returns
/// A map of node numbers to their verified public keys on success.
pub fn verify_roster(
    roster: &Roster,
    verifier_node_number: i32,
    verifier_public_key_spki: &[u8],
) -> Result<HashMap<i32, VerifyingKey>, RosterVerificationError> {
    // 1. Validate structure
    verify_roster_structure(roster)?;

    // 2. Decode all public keys
    let keys = decode_roster_keys(roster)?;

    // 3. Verify the verifier is in the roster with the expected key and not revoked
    let verifier_node = roster
        .nodes
        .iter()
        .find(|n| n.node_number == verifier_node_number)
        .ok_or(RosterVerificationError::VerifierNotInRoster(verifier_node_number))?;

    if verifier_node.revoked {
        return Err(RosterVerificationError::VerifierRevoked(verifier_node_number));
    }

    let verifier_key = keys
        .get(&verifier_node_number)
        .ok_or(RosterVerificationError::VerifierNotInRoster(verifier_node_number))?;

    let expected_verifier_key = VerifyingKey::from_public_key_der(verifier_public_key_spki)
        .map_err(|e| RosterVerificationError::InvalidPublicKey {
            node_number: verifier_node_number,
            reason: e.to_string(),
        })?;

    if verifier_key != &expected_verifier_key {
        return Err(RosterVerificationError::VerifierKeyMismatch(verifier_node_number));
    }

    // 4. Verify the chain of trust backwards from current version to 1
    verify_roster_chain(roster, &keys)?;

    // 5. Return only the active (non-revoked) keys
    let active_keys = roster
        .nodes
        .iter()
        .filter(|n| !n.revoked)
        .filter_map(|n| keys.get(&n.node_number).map(|k| (n.node_number, *k)))
        .collect();

    Ok(active_keys)
}

/// Validate the roster structure (counts match version).
fn verify_roster_structure(roster: &Roster) -> Result<(), RosterVerificationError> {
    if roster.version < 1 {
        return Err(RosterVerificationError::InvalidVersion(roster.version));
    }

    // Version N roster should have:
    // - N+1 nodes (initial node + N activations, minus any revocations)
    // - N addenda (one per version change)
    // Note: With revocations, node count = 1 + activations - revocations
    // We'll validate node count during chain verification instead

    let expected_addenda = roster.version as usize;
    if roster.addenda.len() != expected_addenda {
        return Err(RosterVerificationError::AddendaCountMismatch {
            version: roster.version,
            expected: expected_addenda,
            actual: roster.addenda.len(),
        });
    }

    Ok(())
}

/// Decode all public keys from the roster.
fn decode_roster_keys(roster: &Roster) -> Result<HashMap<i32, VerifyingKey>, RosterVerificationError> {
    let mut keys = HashMap::with_capacity(roster.nodes.len());

    for node in &roster.nodes {
        if keys.contains_key(&node.node_number) {
            return Err(RosterVerificationError::DuplicateNode(node.node_number));
        }

        let key = VerifyingKey::from_public_key_der(&node.public_key_spki).map_err(|e| {
            RosterVerificationError::InvalidPublicKey {
                node_number: node.node_number,
                reason: e.to_string(),
            }
        })?;

        keys.insert(node.node_number, key);
    }

    Ok(keys)
}

/// Verify the chain of signatures and hashes backwards through all versions.
fn verify_roster_chain(
    roster: &Roster,
    keys: &HashMap<i32, VerifyingKey>,
) -> Result<(), RosterVerificationError> {
    // Work on a mutable copy that we'll peel back version by version
    let mut working_roster = roster.clone();

    // Track node state as we go backwards (node_number -> revoked status at this point)
    // We start with the current state and "undo" changes as we go back
    let mut node_revoked: HashMap<i32, bool> = roster
        .nodes
        .iter()
        .map(|n| (n.node_number, n.revoked))
        .collect();

    for version in (1..=roster.version).rev() {
        let addendum_idx = (version - 1) as usize;
        let addendum = working_roster
            .addenda
            .last()
            .ok_or(RosterVerificationError::MissingAddendum(addendum_idx))?
            .clone();

        let kind = addendum
            .kind
            .as_ref()
            .ok_or(RosterVerificationError::EmptyAddendum(addendum_idx))?;

        match kind {
            addendum::Kind::Activation(activation) => {
                verify_activation(&working_roster, activation, version, keys, &mut node_revoked)?;
                // Going backwards: remove the node that was added in this activation
                if let Some(payload) = &activation.payload {
                    working_roster.nodes.retain(|n| n.node_number != payload.new_node_number);
                }
            }
            addendum::Kind::Revocation(revocation) => {
                verify_revocation(&working_roster, revocation, version, keys, &mut node_revoked)?;
                // Going backwards: un-revoke the node
                if let Some(payload) = &revocation.payload {
                    if let Some(node) = working_roster
                        .nodes
                        .iter_mut()
                        .find(|n| n.node_number == payload.revoked_node_number)
                    {
                        node.revoked = false;
                    }
                }
            }
        }

        // Remove the last addendum to get the previous version's roster
        working_roster.addenda.pop();
        working_roster.version -= 1;
    }

    Ok(())
}

/// Verify an activation addendum.
fn verify_activation(
    roster: &Roster,
    activation: &roster::Activation,
    expected_version: i64,
    keys: &HashMap<i32, VerifyingKey>,
    node_revoked: &mut HashMap<i32, bool>,
) -> Result<(), RosterVerificationError> {
    let payload = activation
        .payload
        .as_ref()
        .ok_or(RosterVerificationError::MissingActivationPayload(expected_version))?;

    // Verify version numbers
    if payload.new_version != expected_version {
        return Err(RosterVerificationError::VersionMismatch {
            expected: expected_version,
            actual: payload.new_version,
        });
    }

    // Get keys for signature verification
    let new_node_key = keys
        .get(&payload.new_node_number)
        .ok_or(RosterVerificationError::NewNodeNotInRoster {
            version: expected_version,
            new_node: payload.new_node_number,
        })?;

    let endorser_key = keys
        .get(&payload.endorser_node_number)
        .ok_or(RosterVerificationError::EndorserNotInPreviousRoster {
            version: expected_version,
            endorser: payload.endorser_node_number,
        })?;

    // New node cannot be its own endorser
    if payload.new_node_number == payload.endorser_node_number {
        return Err(RosterVerificationError::NewNodeIsEndorser(payload.new_node_number));
    }

    // For version 1 (bootstrap), both nodes are being added together, so the
    // endorser is also new. For all other versions, the endorser must have been
    // active (not revoked) in the roster before this activation.
    let is_bootstrap = expected_version == 1;
    if !is_bootstrap {
        let endorser_revoked = node_revoked.get(&payload.endorser_node_number);
        if endorser_revoked.is_none() || *endorser_revoked.unwrap() {
            return Err(RosterVerificationError::EndorserNotInPreviousRoster {
                version: expected_version,
                endorser: payload.endorser_node_number,
            });
        }
    }

    // Verify signatures
    let payload_bytes = payload.encode_to_vec();

    verify_signature(new_node_key, &payload_bytes, &activation.new_node_signature)
        .map_err(|_| RosterVerificationError::InvalidNewNodeSignature(expected_version))?;

    verify_signature(endorser_key, &payload_bytes, &activation.endorser_signature)
        .map_err(|_| RosterVerificationError::InvalidEndorserSignature(expected_version))?;

    // Verify base hash (for versions > 1)
    if expected_version > 1 {
        verify_base_hash(roster, payload.base_version, &payload.base_version_hash, expected_version)?;
    }

    // Going backwards: remove this node from tracking (it didn't exist before activation)
    node_revoked.remove(&payload.new_node_number);

    Ok(())
}

/// Verify a revocation addendum.
fn verify_revocation(
    roster: &Roster,
    revocation: &roster::Revocation,
    expected_version: i64,
    keys: &HashMap<i32, VerifyingKey>,
    node_revoked: &mut HashMap<i32, bool>,
) -> Result<(), RosterVerificationError> {
    let payload = revocation
        .payload
        .as_ref()
        .ok_or(RosterVerificationError::MissingRevocationPayload(expected_version))?;

    // Verify version numbers
    if payload.new_version != expected_version {
        return Err(RosterVerificationError::VersionMismatch {
            expected: expected_version,
            actual: payload.new_version,
        });
    }

    // Get revoker's key
    let revoker_key = keys
        .get(&payload.revoker_node_number)
        .ok_or(RosterVerificationError::RevokerNotInPreviousRoster {
            version: expected_version,
            revoker: payload.revoker_node_number,
        })?;

    // Verify revoker was active (not revoked) at the time of this revocation.
    // Since we're going backwards, we need to check their status at this point.
    let revoker_revoked = node_revoked.get(&payload.revoker_node_number);
    if revoker_revoked.is_none() || *revoker_revoked.unwrap() {
        return Err(RosterVerificationError::RevokerNotInPreviousRoster {
            version: expected_version,
            revoker: payload.revoker_node_number,
        });
    }

    // Verify the revoked node exists in the roster
    if !node_revoked.contains_key(&payload.revoked_node_number) {
        return Err(RosterVerificationError::RevokedNodeNotInRoster {
            version: expected_version,
            revoked: payload.revoked_node_number,
        });
    }

    // Verify signature
    let payload_bytes = payload.encode_to_vec();

    verify_signature(revoker_key, &payload_bytes, &revocation.revoker_signature)
        .map_err(|_| RosterVerificationError::InvalidRevokerSignature(expected_version))?;

    // Verify base hash (for versions > 1)
    if expected_version > 1 {
        verify_base_hash(roster, payload.base_version, &payload.base_version_hash, expected_version)?;
    }

    // Going backwards: un-revoke this node (it was active before this revocation)
    node_revoked.insert(payload.revoked_node_number, false);

    Ok(())
}

/// Verify a signature.
fn verify_signature(
    key: &VerifyingKey,
    message: &[u8],
    signature_bytes: &[u8],
) -> Result<(), ()> {
    let signature = Signature::from_slice(signature_bytes).map_err(|_| ())?;
    key.verify(message, &signature).map_err(|_| ())
}

/// Verify the base version hash matches the reconstructed previous roster.
fn verify_base_hash(
    roster: &Roster,
    base_version: i64,
    expected_hash: &[u8],
    current_version: i64,
) -> Result<(), RosterVerificationError> {
    // Reconstruct the roster at base_version by walking backwards
    let mut base_roster = roster.clone();

    // Walk backwards from current version to base_version+1, undoing changes
    for i in (base_version as usize..roster.addenda.len()).rev() {
        if let Some(addendum) = roster.addenda.get(i) {
            if let Some(kind) = &addendum.kind {
                match kind {
                    addendum::Kind::Activation(activation) => {
                        // Remove the node that was activated (it didn't exist at base_version)
                        if let Some(payload) = &activation.payload {
                            base_roster.nodes.retain(|n| n.node_number != payload.new_node_number);
                        }
                    }
                    addendum::Kind::Revocation(revocation) => {
                        // Un-revoke the node (it was active at base_version)
                        if let Some(payload) = &revocation.payload {
                            if let Some(node) = base_roster
                                .nodes
                                .iter_mut()
                                .find(|n| n.node_number == payload.revoked_node_number)
                            {
                                node.revoked = false;
                            }
                        }
                    }
                }
            }
        }
    }

    // Set version and truncate addenda
    base_roster.version = base_version;
    base_roster.addenda.truncate(base_version as usize);

    let hash = compute_roster_hash(&base_roster);

    if hash != expected_hash {
        return Err(RosterVerificationError::BaseHashMismatch(current_version));
    }

    Ok(())
}

/// Compute the SHA256 hash of a roster for version verification.
fn compute_roster_hash(roster: &Roster) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(roster.encode_to_vec());
    hasher.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::pkcs8::EncodePublicKey;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    /// Generate a random signing key for testing.
    fn generate_key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    /// Get the SPKI-encoded public key.
    fn spki(key: &SigningKey) -> Vec<u8> {
        key.verifying_key()
            .to_public_key_der()
            .expect("SPKI encoding")
            .to_vec()
    }

    /// Sign a message with a signing key.
    fn sign(key: &SigningKey, message: &[u8]) -> Vec<u8> {
        use ed25519_dalek::Signer;
        key.sign(message).to_bytes().to_vec()
    }

    /// Build a version 1 (bootstrap) roster with two founding nodes.
    ///
    /// Bootstrap requires two nodes to establish mutual trust before any roster exists.
    /// The version 1 roster contains both nodes and a single addendum recording their
    /// mutual bootstrap, signed by both.
    fn build_bootstrap_roster(
        key_a: &SigningKey,
        node_a: i32,
        key_b: &SigningKey,
        node_b: i32,
    ) -> Roster {
        // Version 1 roster has 2 nodes and 1 addendum (the bootstrap activation)
        // Node B is the "new node" being activated, endorsed by node A
        let payload = roster::activation::Payload {
            base_version: 0,
            base_version_hash: vec![],
            new_version: 1,
            new_node_number: node_b,
            endorser_node_number: node_a,
            new_node_nonce: b"node_b_nonce".to_vec(),
            endorser_nonce: b"node_a_nonce".to_vec(),
        };
        let payload_bytes = payload.encode_to_vec();

        Roster {
            version: 1,
            nodes: vec![
                roster::Node {
                    node_number: node_a,
                    public_key_spki: spki(key_a),
                    revoked: false,
                },
                roster::Node {
                    node_number: node_b,
                    public_key_spki: spki(key_b),
                    revoked: false,
                },
            ],
            addenda: vec![roster::Addendum {
                kind: Some(addendum::Kind::Activation(roster::Activation {
                    payload: Some(payload),
                    new_node_signature: sign(key_b, &payload_bytes),
                    endorser_signature: sign(key_a, &payload_bytes),
                })),
            }],
        }
    }

    /// Add a new node to the roster (activation).
    fn add_node(
        roster: &mut Roster,
        new_key: &SigningKey,
        new_node_number: i32,
        endorser_key: &SigningKey,
        endorser_node_number: i32,
    ) {
        let base_hash = compute_roster_hash(roster);
        let new_version = roster.version + 1;

        let payload = roster::activation::Payload {
            base_version: roster.version,
            base_version_hash: base_hash,
            new_version,
            new_node_number,
            endorser_node_number,
            new_node_nonce: format!("nonce_{}", new_node_number).into_bytes(),
            endorser_nonce: format!("endorser_nonce_{}", new_version).into_bytes(),
        };
        let payload_bytes = payload.encode_to_vec();

        roster.version = new_version;
        roster.nodes.push(roster::Node {
            node_number: new_node_number,
            public_key_spki: spki(new_key),
            revoked: false,
        });
        roster.addenda.push(roster::Addendum {
            kind: Some(addendum::Kind::Activation(roster::Activation {
                payload: Some(payload),
                new_node_signature: sign(new_key, &payload_bytes),
                endorser_signature: sign(endorser_key, &payload_bytes),
            })),
        });
    }

    /// Revoke a node from the roster.
    fn revoke_node(
        roster: &mut Roster,
        revoked_node_number: i32,
        revoker_key: &SigningKey,
        revoker_node_number: i32,
    ) {
        let base_hash = compute_roster_hash(roster);
        let new_version = roster.version + 1;

        let payload = roster::revocation::Payload {
            base_version: roster.version,
            base_version_hash: base_hash,
            new_version,
            revoked_node_number,
            revoker_node_number,
        };
        let payload_bytes = payload.encode_to_vec();

        roster.version = new_version;
        // Mark the node as revoked
        if let Some(node) = roster.nodes.iter_mut().find(|n| n.node_number == revoked_node_number) {
            node.revoked = true;
        }
        roster.addenda.push(roster::Addendum {
            kind: Some(addendum::Kind::Revocation(roster::Revocation {
                payload: Some(payload),
                revoker_signature: sign(revoker_key, &payload_bytes),
            })),
        });
    }

    // ==================== Basic structure tests ====================

    #[test]
    fn test_invalid_version_zero() {
        let roster = Roster {
            version: 0,
            nodes: vec![],
            addenda: vec![],
        };
        let result = verify_roster(&roster, 1, &[]);
        assert!(matches!(result, Err(RosterVerificationError::InvalidVersion(0))));
    }

    #[test]
    fn test_addenda_count_mismatch() {
        let roster = Roster {
            version: 2,
            nodes: vec![],
            addenda: vec![], // Should have 2 addenda
        };
        let result = verify_roster(&roster, 1, &[]);
        assert!(matches!(
            result,
            Err(RosterVerificationError::AddendaCountMismatch { .. })
        ));
    }

    #[test]
    fn test_duplicate_node_numbers() {
        let key = generate_key();
        let roster = Roster {
            version: 1,
            nodes: vec![
                roster::Node {
                    node_number: 1,
                    public_key_spki: spki(&key),
                    revoked: false,
                },
                roster::Node {
                    node_number: 1, // Duplicate!
                    public_key_spki: spki(&key),
                    revoked: false,
                },
            ],
            addenda: vec![roster::Addendum { kind: None }],
        };
        let result = verify_roster(&roster, 1, &spki(&key));
        assert!(matches!(result, Err(RosterVerificationError::DuplicateNode(1))));
    }

    // ==================== Verifier validation tests ====================

    #[test]
    fn test_verifier_not_in_roster() {
        let key_a = generate_key();
        let key_b = generate_key();
        let roster = build_bootstrap_roster(&key_a, 1, &key_b, 2);
        let other_key = generate_key();
        // Node 99 doesn't exist
        let result = verify_roster(&roster, 99, &spki(&other_key));
        assert!(matches!(
            result,
            Err(RosterVerificationError::VerifierNotInRoster(99))
        ));
    }

    #[test]
    fn test_verifier_key_mismatch() {
        let key_a = generate_key();
        let key_b = generate_key();
        let roster = build_bootstrap_roster(&key_a, 1, &key_b, 2);
        let wrong_key = generate_key();
        // Right node number, wrong key
        let result = verify_roster(&roster, 1, &spki(&wrong_key));
        assert!(matches!(
            result,
            Err(RosterVerificationError::VerifierKeyMismatch(1))
        ));
    }

    #[test]
    fn test_verifier_revoked() {
        let key1 = generate_key();
        let key2 = generate_key();
        let key3 = generate_key();
        let mut roster = build_bootstrap_roster(&key1, 1, &key2, 2);
        add_node(&mut roster, &key3, 3, &key1, 1);
        revoke_node(&mut roster, 1, &key3, 3);

        // Node 1 is now revoked, should fail verification as verifier
        let result = verify_roster(&roster, 1, &spki(&key1));
        assert!(matches!(
            result,
            Err(RosterVerificationError::VerifierRevoked(1))
        ));
    }

    // ==================== Successful verification tests ====================

    #[test]
    fn test_bootstrap_roster_verifies() {
        let key_a = generate_key();
        let key_b = generate_key();
        let roster = build_bootstrap_roster(&key_a, 1, &key_b, 2);
        // Both founding nodes should be able to verify
        let result = verify_roster(&roster, 1, &spki(&key_a));
        assert!(result.is_ok());
        let keys = result.unwrap();
        assert_eq!(keys.len(), 2);
        assert!(keys.contains_key(&1));
        assert!(keys.contains_key(&2));

        let result = verify_roster(&roster, 2, &spki(&key_b));
        assert!(result.is_ok());
    }

    #[test]
    fn test_multi_node_roster_verifies() {
        let key1 = generate_key();
        let key2 = generate_key();
        let key3 = generate_key();
        let key4 = generate_key();

        // Bootstrap with key1 (node 1) and key2 (node 2)
        let mut roster = build_bootstrap_roster(&key1, 1, &key2, 2);
        add_node(&mut roster, &key3, 3, &key2, 2);
        add_node(&mut roster, &key4, 4, &key1, 1);

        // All nodes should be able to verify
        for (node_num, key) in [(1, &key1), (2, &key2), (3, &key3), (4, &key4)] {
            let result = verify_roster(&roster, node_num, &spki(key));
            assert!(result.is_ok(), "Node {} should verify successfully", node_num);
            let keys = result.unwrap();
            assert_eq!(keys.len(), 4);
        }
    }

    #[test]
    fn test_verification_during_roster_growth() {
        // Similar to Go test: verify at each step of building a roster
        let keys: Vec<_> = (0..5).map(|_| generate_key()).collect();

        // Bootstrap with keys[0] (node 0) and keys[1] (node 1)
        let mut roster = build_bootstrap_roster(&keys[0], 0, &keys[1], 1);

        // After bootstrap, nodes 0 and 1 should verify
        for j in 0..5 {
            let result = verify_roster(&roster, j as i32, &spki(&keys[j]));
            if j <= 1 {
                assert!(
                    result.is_ok(),
                    "Node {} should verify at version {}",
                    j,
                    roster.version
                );
            } else {
                assert!(
                    result.is_err(),
                    "Node {} should NOT verify at version {}",
                    j,
                    roster.version
                );
            }
        }

        // Now add nodes 2, 3, 4
        for i in 2..5 {
            add_node(&mut roster, &keys[i], i as i32, &keys[i - 1], (i - 1) as i32);

            // Verify that nodes in the roster can verify, nodes not yet added cannot
            for j in 0..5 {
                let result = verify_roster(&roster, j as i32, &spki(&keys[j]));
                if j <= i {
                    assert!(
                        result.is_ok(),
                        "Node {} should verify at version {}",
                        j,
                        roster.version
                    );
                } else {
                    assert!(
                        result.is_err(),
                        "Node {} should NOT verify at version {}",
                        j,
                        roster.version
                    );
                }
            }
        }
    }

    // ==================== Signature verification tests ====================

    #[test]
    fn test_invalid_new_node_signature() {
        let key1 = generate_key();
        let key2 = generate_key();
        let key3 = generate_key();
        let mut roster = build_bootstrap_roster(&key1, 1, &key2, 2);
        add_node(&mut roster, &key3, 3, &key1, 1);

        // Corrupt the new node signature on the activation of node 3
        if let Some(addendum::Kind::Activation(ref mut act)) = roster.addenda[1].kind {
            act.new_node_signature = vec![0u8; 64]; // Invalid signature
        }

        let result = verify_roster(&roster, 1, &spki(&key1));
        assert!(matches!(
            result,
            Err(RosterVerificationError::InvalidNewNodeSignature(2))
        ));
    }

    #[test]
    fn test_invalid_endorser_signature() {
        let key1 = generate_key();
        let key2 = generate_key();
        let key3 = generate_key();
        let mut roster = build_bootstrap_roster(&key1, 1, &key2, 2);
        add_node(&mut roster, &key3, 3, &key1, 1);

        // Corrupt the endorser signature on the activation of node 3
        if let Some(addendum::Kind::Activation(ref mut act)) = roster.addenda[1].kind {
            act.endorser_signature = vec![0u8; 64]; // Invalid signature
        }

        let result = verify_roster(&roster, 1, &spki(&key1));
        assert!(matches!(
            result,
            Err(RosterVerificationError::InvalidEndorserSignature(2))
        ));
    }

    #[test]
    fn test_flipped_signatures() {
        let key1 = generate_key();
        let key2 = generate_key();
        let key3 = generate_key();
        let key4 = generate_key();
        let mut roster = build_bootstrap_roster(&key1, 1, &key2, 2);
        add_node(&mut roster, &key3, 3, &key2, 2);
        add_node(&mut roster, &key4, 4, &key1, 1);

        // Flip the signatures on the last addendum (node 4 activation)
        if let Some(addendum::Kind::Activation(ref mut act)) = roster.addenda[2].kind {
            std::mem::swap(&mut act.new_node_signature, &mut act.endorser_signature);
        }

        let result = verify_roster(&roster, 1, &spki(&key1));
        assert!(result.is_err());
    }

    // ==================== Base hash tests ====================

    #[test]
    fn test_bad_base_hash() {
        let key1 = generate_key();
        let key2 = generate_key();
        let key3 = generate_key();
        let mut roster = build_bootstrap_roster(&key1, 1, &key2, 2);
        add_node(&mut roster, &key3, 3, &key1, 1);

        // Corrupt the base hash on the activation of node 3
        if let Some(addendum::Kind::Activation(ref mut act)) = roster.addenda[1].kind {
            if let Some(ref mut payload) = act.payload {
                payload.base_version_hash = b"fake_hash".to_vec();
            }
        }

        let result = verify_roster(&roster, 1, &spki(&key1));
        assert!(result.is_err(), "Should fail with corrupted base hash, got: {:?}", result);
        // The error could be BaseHashMismatch or InvalidSignature (since we changed the payload)
        let err = result.unwrap_err();
        assert!(
            matches!(err, RosterVerificationError::BaseHashMismatch(2))
            || matches!(err, RosterVerificationError::InvalidNewNodeSignature(2))
            || matches!(err, RosterVerificationError::InvalidEndorserSignature(2)),
            "Expected BaseHashMismatch or signature error, got: {:?}", err
        );
    }

    // ==================== Cross-reference tests ====================

    #[test]
    fn test_self_endorsement_rejected() {
        let key1 = generate_key();
        let key2 = generate_key();
        let key3 = generate_key();
        let mut roster = build_bootstrap_roster(&key1, 1, &key2, 2);

        // Try to add node 3 with self-endorsement (node 3 endorses itself)
        let base_hash = compute_roster_hash(&roster);
        let payload = roster::activation::Payload {
            base_version: roster.version,
            base_version_hash: base_hash,
            new_version: 2,
            new_node_number: 3,
            endorser_node_number: 3, // Self-endorsement!
            new_node_nonce: b"nonce".to_vec(),
            endorser_nonce: b"endorser_nonce".to_vec(),
        };
        let payload_bytes = payload.encode_to_vec();

        roster.version = 2;
        roster.nodes.push(roster::Node {
            node_number: 3,
            public_key_spki: spki(&key3),
            revoked: false,
        });
        roster.addenda.push(roster::Addendum {
            kind: Some(addendum::Kind::Activation(roster::Activation {
                payload: Some(payload),
                new_node_signature: sign(&key3, &payload_bytes),
                endorser_signature: sign(&key3, &payload_bytes), // Same key signs both
            })),
        });

        let result = verify_roster(&roster, 1, &spki(&key1));
        assert!(matches!(
            result,
            Err(RosterVerificationError::NewNodeIsEndorser(3))
        ));
    }

    #[test]
    fn test_endorser_not_in_roster() {
        let key1 = generate_key();
        let key2 = generate_key();
        let key3 = generate_key();
        let mut roster = build_bootstrap_roster(&key1, 1, &key2, 2);

        // Manually create an addendum claiming endorser node 99 (doesn't exist)
        let base_hash = compute_roster_hash(&roster);
        let payload = roster::activation::Payload {
            base_version: roster.version,
            base_version_hash: base_hash,
            new_version: 2,
            new_node_number: 3,
            endorser_node_number: 99, // Doesn't exist!
            new_node_nonce: b"nonce".to_vec(),
            endorser_nonce: b"endorser_nonce".to_vec(),
        };
        let payload_bytes = payload.encode_to_vec();

        roster.version = 2;
        roster.nodes.push(roster::Node {
            node_number: 3,
            public_key_spki: spki(&key3),
            revoked: false,
        });
        roster.addenda.push(roster::Addendum {
            kind: Some(addendum::Kind::Activation(roster::Activation {
                payload: Some(payload),
                new_node_signature: sign(&key3, &payload_bytes),
                endorser_signature: sign(&key1, &payload_bytes), // Wrong key but doesn't matter
            })),
        });

        let result = verify_roster(&roster, 1, &spki(&key1));
        assert!(matches!(
            result,
            Err(RosterVerificationError::EndorserNotInPreviousRoster { .. })
        ));
    }

    // ==================== Revocation tests ====================

    #[test]
    fn test_revocation_verifies() {
        let key1 = generate_key();
        let key2 = generate_key();
        let key3 = generate_key();
        let mut roster = build_bootstrap_roster(&key1, 1, &key2, 2);
        add_node(&mut roster, &key3, 3, &key1, 1);
        revoke_node(&mut roster, 1, &key3, 3);

        // Node 3 (the revoker, still active) should be able to verify
        let result = verify_roster(&roster, 3, &spki(&key3));
        assert!(result.is_ok());

        // Nodes 2 and 3 should be in the active keys, not node 1
        let keys = result.unwrap();
        assert_eq!(keys.len(), 2);
        assert!(keys.contains_key(&2));
        assert!(keys.contains_key(&3));
        assert!(!keys.contains_key(&1)); // Node 1 was revoked
    }

    #[test]
    fn test_invalid_revoker_signature() {
        let key1 = generate_key();
        let key2 = generate_key();
        let key3 = generate_key();
        let mut roster = build_bootstrap_roster(&key1, 1, &key2, 2);
        add_node(&mut roster, &key3, 3, &key1, 1);
        revoke_node(&mut roster, 1, &key3, 3);

        // Corrupt the revoker signature
        if let Some(addendum::Kind::Revocation(ref mut rev)) = roster.addenda[2].kind {
            rev.revoker_signature = vec![0u8; 64];
        }

        let result = verify_roster(&roster, 2, &spki(&key2));
        assert!(matches!(
            result,
            Err(RosterVerificationError::InvalidRevokerSignature(3))
        ));
    }

    #[test]
    fn test_revoked_node_cannot_endorse() {
        let key1 = generate_key();
        let key2 = generate_key();
        let key3 = generate_key();
        let key4 = generate_key();
        let mut roster = build_bootstrap_roster(&key1, 1, &key2, 2);
        add_node(&mut roster, &key3, 3, &key1, 1);
        revoke_node(&mut roster, 1, &key3, 3);

        // Try to have revoked node 1 endorse node 4
        // This would fail because node 1 is revoked
        let base_hash = compute_roster_hash(&roster);
        let payload = roster::activation::Payload {
            base_version: roster.version,
            base_version_hash: base_hash,
            new_version: roster.version + 1,
            new_node_number: 4,
            endorser_node_number: 1, // Revoked!
            new_node_nonce: b"nonce".to_vec(),
            endorser_nonce: b"endorser_nonce".to_vec(),
        };
        let payload_bytes = payload.encode_to_vec();

        roster.version += 1;
        roster.nodes.push(roster::Node {
            node_number: 4,
            public_key_spki: spki(&key4),
            revoked: false,
        });
        roster.addenda.push(roster::Addendum {
            kind: Some(addendum::Kind::Activation(roster::Activation {
                payload: Some(payload),
                new_node_signature: sign(&key4, &payload_bytes),
                endorser_signature: sign(&key1, &payload_bytes),
            })),
        });

        let result = verify_roster(&roster, 2, &spki(&key2));
        assert!(matches!(
            result,
            Err(RosterVerificationError::EndorserNotInPreviousRoster { .. })
        ));
    }

    #[test]
    fn test_revoked_node_cannot_revoke() {
        let key1 = generate_key();
        let key2 = generate_key();
        let key3 = generate_key();
        let key4 = generate_key();
        let mut roster = build_bootstrap_roster(&key1, 1, &key2, 2);
        add_node(&mut roster, &key3, 3, &key2, 2);
        add_node(&mut roster, &key4, 4, &key3, 3);
        revoke_node(&mut roster, 1, &key2, 2);

        // Try to have revoked node 1 revoke node 4
        let base_hash = compute_roster_hash(&roster);
        let payload = roster::revocation::Payload {
            base_version: roster.version,
            base_version_hash: base_hash,
            new_version: roster.version + 1,
            revoked_node_number: 4,
            revoker_node_number: 1, // Revoked!
        };
        let payload_bytes = payload.encode_to_vec();

        roster.version += 1;
        if let Some(node) = roster.nodes.iter_mut().find(|n| n.node_number == 4) {
            node.revoked = true;
        }
        roster.addenda.push(roster::Addendum {
            kind: Some(addendum::Kind::Revocation(roster::Revocation {
                payload: Some(payload),
                revoker_signature: sign(&key1, &payload_bytes),
            })),
        });

        let result = verify_roster(&roster, 2, &spki(&key2));
        assert!(matches!(
            result,
            Err(RosterVerificationError::RevokerNotInPreviousRoster { .. })
        ));
    }

    // ==================== active_nodes helper tests ====================

    #[test]
    fn test_active_nodes_filters_revoked() {
        let key1 = generate_key();
        let key2 = generate_key();
        let key3 = generate_key();
        let key4 = generate_key();
        let mut roster = build_bootstrap_roster(&key1, 1, &key2, 2);
        add_node(&mut roster, &key3, 3, &key1, 1);
        add_node(&mut roster, &key4, 4, &key2, 2);
        revoke_node(&mut roster, 3, &key4, 4);

        let active: Vec<_> = active_nodes(&roster).collect();
        assert_eq!(active.len(), 3);
        assert!(active.iter().any(|n| n.node_number == 1));
        assert!(active.iter().any(|n| n.node_number == 2));
        assert!(active.iter().any(|n| n.node_number == 4));
        assert!(!active.iter().any(|n| n.node_number == 3)); // Revoked
    }

    // ==================== Complex scenario tests ====================

    #[test]
    fn test_complex_roster_lifecycle() {
        // Build a roster with multiple activations and revocations
        let keys: Vec<_> = (0..6).map(|_| generate_key()).collect();

        // Bootstrap with keys[0] (node 0) and keys[1] (node 1)
        let mut roster = build_bootstrap_roster(&keys[0], 0, &keys[1], 1);
        add_node(&mut roster, &keys[2], 2, &keys[1], 1); // v2: add node 2
        add_node(&mut roster, &keys[3], 3, &keys[0], 0); // v3: add node 3
        add_node(&mut roster, &keys[4], 4, &keys[2], 2); // v4: add node 4
        revoke_node(&mut roster, 1, &keys[2], 2);        // v5: revoke node 1
        add_node(&mut roster, &keys[5], 5, &keys[3], 3); // v6: add node 5

        // Verify from each active node's perspective
        for &active_node in &[0, 2, 3, 4, 5] {
            let result = verify_roster(&roster, active_node, &spki(&keys[active_node as usize]));
            assert!(result.is_ok(), "Node {} should verify", active_node);

            let verified_keys = result.unwrap();
            assert_eq!(verified_keys.len(), 5); // 6 nodes - 1 revoked = 5 active
            assert!(!verified_keys.contains_key(&1)); // Node 1 was revoked
        }

        // Revoked node 1 should fail to verify
        let result = verify_roster(&roster, 1, &spki(&keys[1]));
        assert!(matches!(result, Err(RosterVerificationError::VerifierRevoked(1))));
    }
}
