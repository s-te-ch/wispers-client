//! Roster verification for Wispers Connect.
//!
//! This module provides cryptographic verification of the roster, ensuring the
//! chain of trust from version 1 to the current version is valid.

use crate::hub::proto::roster::{self, Roster, addendum};
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

    #[error("version mismatch in addendum: expected {expected}, got {actual}")]
    VersionMismatch { expected: i64, actual: i64 },

    #[error(
        "reconstructed roster does not match input \
         (the hub may have tampered with the nodes list directly, \
         bypassing the addenda chain)"
    )]
    ReconstructionMismatch,
}

/// Verify a roster's cryptographic integrity by reconstruction.
///
/// Walks the addenda forward from version 1, building up a `working_roster`
/// step by step. At each step:
///   1. Verifies structural rules (version number, no self-endorsement, etc.)
///   2. Verifies the addendum's signatures using keys accumulated from
///      previous addenda (or, for the bootstrap, from the input roster's
///      nodes list — those keys are then locked in by the hash check).
///   3. Applies the addendum to `working_roster`.
///   4. Recomputes `new_version_hash` over the resulting `working_roster`
///      and checks it matches the value the signers committed to.
///
/// After the walk, two final checks:
///   - The reconstructed `working_roster` must equal the input roster
///     byte-for-byte. This catches tampering of `Roster.nodes` that bypasses
///     the addenda chain (e.g., a hub adding a phantom node entry that no
///     addendum mentions).
///   - The verifier (caller) must be in the final state with the expected
///     public key and not revoked. This is the trust anchor that ties the
///     internally-consistent reconstruction to real-world identity.
///
/// # Arguments
/// * `roster` - The roster to verify
/// * `verifier_node_number` - The node number of the verifier (must be in
///   the final state)
/// * `verifier_public_key_spki` - The verifier's expected public key in SPKI
///   DER format
///
/// # Returns
/// A map of node numbers to their verified public keys on success (active
/// nodes only).
///
/// # Errors
///
/// Returns `Err` if the roster structure is invalid, signature verification fails,
/// or the verifier node is not found or revoked.
///
/// # Panics
///
/// Panics if `verifier_public_key_spki` is not a valid SPKI-encoded Ed25519 public key.
pub fn verify_roster(
    roster: &Roster,
    verifier_node_number: i32,
    verifier_public_key_spki: &[u8],
) -> Result<HashMap<i32, VerifyingKey>, RosterVerificationError> {
    // Decode the verifier's expected key. The caller derives this from its own
    // root key, so a parse failure here means a programming bug, not a
    // verification failure.
    let expected_verifier_key = VerifyingKey::from_public_key_der(verifier_public_key_spki)
        .expect("verifier_public_key_spki must be valid SPKI-encoded Ed25519");

    // Sanity-check the structure (provides clearer errors than the walk would).
    verify_roster_structure(roster)?;

    // Forward walk: reconstruct the roster from scratch by applying each
    // addendum, verifying as we go. After this loop, `working_roster`
    // represents the canonical state implied by the addenda alone.
    let mut working_roster = Roster::default();
    let mut keys: HashMap<i32, VerifyingKey> = HashMap::new();
    for (i, addendum) in roster.addenda.iter().enumerate() {
        let expected_version = i64::try_from(i + 1).expect("addendum index fits i64");
        let kind = addendum
            .kind
            .as_ref()
            .ok_or(RosterVerificationError::EmptyAddendum(i))?;
        match kind {
            addendum::Kind::Activation(activation) => {
                apply_and_verify_activation(
                    roster,
                    activation,
                    expected_version,
                    &mut working_roster,
                    &mut keys,
                )?;
            }
            addendum::Kind::Revocation(revocation) => {
                apply_and_verify_revocation(
                    revocation,
                    expected_version,
                    &mut working_roster,
                    &mut keys,
                )?;
            }
        }
    }

    // The reconstructed roster must equal the input. This catches
    // tampering with `Roster.nodes` that doesn't show up in any addendum
    // (e.g. a phantom entry added directly by the hub).
    if working_roster != *roster {
        return Err(RosterVerificationError::ReconstructionMismatch);
    }

    // Verifier anchor: the caller must currently be active with the key
    // they claim. Membership in `keys` is the active-set test; we fall
    // back to scanning `working_roster.nodes` only to distinguish "never
    // in the roster" from "revoked".
    let Some(verifier_key_in_state) = keys.get(&verifier_node_number) else {
        if working_roster
            .nodes
            .iter()
            .any(|n| n.node_number == verifier_node_number)
        {
            return Err(RosterVerificationError::VerifierRevoked(
                verifier_node_number,
            ));
        }
        return Err(RosterVerificationError::VerifierNotInRoster(
            verifier_node_number,
        ));
    };
    if verifier_key_in_state != &expected_verifier_key {
        return Err(RosterVerificationError::VerifierKeyMismatch(
            verifier_node_number,
        ));
    }

    // Return the active keys.
    Ok(keys)
}

/// Validate the roster structure (counts match version).
///
/// Cheap pre-flight check that produces clear errors before the forward walk
/// runs. The walk would catch the same issues but with less informative
/// errors.
fn verify_roster_structure(roster: &Roster) -> Result<(), RosterVerificationError> {
    if roster.version < 1 {
        return Err(RosterVerificationError::InvalidVersion(roster.version));
    }

    let expected_addenda = usize::try_from(roster.version).expect("roster version fits usize");
    if roster.addenda.len() != expected_addenda {
        return Err(RosterVerificationError::AddendaCountMismatch {
            version: roster.version,
            expected: expected_addenda,
            actual: roster.addenda.len(),
        });
    }

    Ok(())
}

/// Apply an activation addendum to `working_roster` and verify it.
///
/// On success, `working_roster` and `keys` are updated to reflect the new
/// state. On failure, they may be partially updated; callers must discard
/// them.
fn apply_and_verify_activation(
    input_roster: &Roster,
    activation: &roster::Activation,
    expected_version: i64,
    working_roster: &mut Roster,
    keys: &mut HashMap<i32, VerifyingKey>,
) -> Result<(), RosterVerificationError> {
    let payload =
        activation
            .payload
            .as_ref()
            .ok_or(RosterVerificationError::MissingActivationPayload(
                expected_version,
            ))?;

    // Version number sanity.
    if payload.version != expected_version {
        return Err(RosterVerificationError::VersionMismatch {
            expected: expected_version,
            actual: payload.version,
        });
    }

    // Self-endorsement is forbidden.
    if payload.new_node_number == payload.endorser_node_number {
        return Err(RosterVerificationError::NewNodeIsEndorser(
            payload.new_node_number,
        ));
    }

    // Reject duplicate activations: a node can only be activated once.
    // (We don't allow re-activation of revoked nodes either — the chain
    // history would still have their original entry, and reusing the same
    // node_number would create ambiguity in `working_roster.nodes`.)
    if working_roster
        .nodes
        .iter()
        .any(|n| n.node_number == payload.new_node_number)
    {
        return Err(RosterVerificationError::DuplicateNode(
            payload.new_node_number,
        ));
    }

    // Look up the new node's pubkey from the input roster (the new node is
    // about to be added; nobody knows it yet).
    let new_node_in_input = input_roster
        .nodes
        .iter()
        .find(|n| n.node_number == payload.new_node_number)
        .ok_or(RosterVerificationError::NewNodeNotInRoster {
            version: expected_version,
            new_node: payload.new_node_number,
        })?;
    let new_node_key = VerifyingKey::from_public_key_der(&new_node_in_input.public_key_spki)
        .map_err(|e| RosterVerificationError::InvalidPublicKey {
            node_number: payload.new_node_number,
            reason: e.to_string(),
        })?;

    // Look up the endorser's pubkey. For the bootstrap (v1), the endorser
    // is also being added — we look them up from the input roster too. For
    // every other version, the endorser must already be active in `keys`.
    let endorser_key = if expected_version == 1 {
        let endorser_in_input = input_roster
            .nodes
            .iter()
            .find(|n| n.node_number == payload.endorser_node_number)
            .ok_or(RosterVerificationError::EndorserNotInPreviousRoster {
                version: expected_version,
                endorser: payload.endorser_node_number,
            })?;
        VerifyingKey::from_public_key_der(&endorser_in_input.public_key_spki).map_err(|e| {
            RosterVerificationError::InvalidPublicKey {
                node_number: payload.endorser_node_number,
                reason: e.to_string(),
            }
        })?
    } else {
        *keys.get(&payload.endorser_node_number).ok_or(
            RosterVerificationError::EndorserNotInPreviousRoster {
                version: expected_version,
                endorser: payload.endorser_node_number,
            },
        )?
    };

    // Apply the addendum to `working_roster`. For the bootstrap, the endorser
    // is added too (and added *first*, matching the canonical order produced by
    // `create_bootstrap_roster`).
    if expected_version == 1 {
        let endorser_in_input = input_roster
            .nodes
            .iter()
            .find(|n| n.node_number == payload.endorser_node_number)
            .expect("checked above");
        working_roster.nodes.push(roster::Node {
            node_number: payload.endorser_node_number,
            public_key_spki: endorser_in_input.public_key_spki.clone(),
            revoked: false,
        });
        keys.insert(payload.endorser_node_number, endorser_key);
    }
    working_roster.nodes.push(roster::Node {
        node_number: payload.new_node_number,
        public_key_spki: new_node_in_input.public_key_spki.clone(),
        revoked: false,
    });
    keys.insert(payload.new_node_number, new_node_key);
    working_roster.version = expected_version;

    // Push the addendum into `working_roster` with empty signatures. This is
    // the state that actually gets hashed and signed.
    working_roster.addenda.push(roster::Addendum {
        kind: Some(addendum::Kind::Activation(roster::Activation {
            payload: Some(payload.clone()),
            new_node_signature: Vec::new(),
            endorser_signature: Vec::new(),
        })),
    });

    // Compute the signing hash and verify both signatures against it.
    let signing_hash = compute_signing_hash(working_roster);
    verify_signature(&new_node_key, &signing_hash, &activation.new_node_signature)
        .map_err(|()| RosterVerificationError::InvalidNewNodeSignature(expected_version))?;
    verify_signature(&endorser_key, &signing_hash, &activation.endorser_signature)
        .map_err(|()| RosterVerificationError::InvalidEndorserSignature(expected_version))?;

    // Now that they're verified, copy the input signatures into the addendum.
    set_new_node_signature(working_roster, activation.new_node_signature.clone());
    set_endorser_signature(working_roster, activation.endorser_signature.clone());

    Ok(())
}

/// Apply a revocation addendum to `working_roster` and verify it.
///
/// Same contract as `apply_and_verify_activation`: on success, the inputs
/// are updated; on failure, they may be partially updated.
fn apply_and_verify_revocation(
    revocation: &roster::Revocation,
    expected_version: i64,
    working_roster: &mut Roster,
    keys: &mut HashMap<i32, VerifyingKey>,
) -> Result<(), RosterVerificationError> {
    let payload =
        revocation
            .payload
            .as_ref()
            .ok_or(RosterVerificationError::MissingRevocationPayload(
                expected_version,
            ))?;

    // Version number sanity.
    if payload.version != expected_version {
        return Err(RosterVerificationError::VersionMismatch {
            expected: expected_version,
            actual: payload.version,
        });
    }

    // The revoker must be currently active. Per the `keys` invariant,
    // membership in `keys` ⇔ active in `working_roster`.
    let revoker_key = *keys.get(&payload.revoker_node_number).ok_or(
        RosterVerificationError::RevokerNotInPreviousRoster {
            version: expected_version,
            revoker: payload.revoker_node_number,
        },
    )?;

    // The revoked node must also be currently active.
    if !keys.contains_key(&payload.revoked_node_number) {
        return Err(RosterVerificationError::RevokedNodeNotInRoster {
            version: expected_version,
            revoked: payload.revoked_node_number,
        });
    }

    // Apply the addendum: mark the revoked node, bump the version, push
    // a fresh addendum with an empty signature.
    if let Some(node) = working_roster
        .nodes
        .iter_mut()
        .find(|n| n.node_number == payload.revoked_node_number)
    {
        node.revoked = true;
    }
    working_roster.version = expected_version;
    working_roster.addenda.push(roster::Addendum {
        kind: Some(addendum::Kind::Revocation(roster::Revocation {
            payload: Some(*payload),
            revoker_signature: Vec::new(),
        })),
    });

    // Compute the signing hash and verify the revoker's signature.
    let signing_hash = compute_signing_hash(working_roster);
    verify_signature(&revoker_key, &signing_hash, &revocation.revoker_signature)
        .map_err(|()| RosterVerificationError::InvalidRevokerSignature(expected_version))?;

    // Now that it's verified, copy the revoker's signature into the addendum.
    set_revoker_signature(working_roster, revocation.revoker_signature.clone());

    // Drop the revoked node from `keys`.
    keys.remove(&payload.revoked_node_number);

    Ok(())
}

/// Verify a signature.
fn verify_signature(key: &VerifyingKey, message: &[u8], signature_bytes: &[u8]) -> Result<(), ()> {
    let signature = Signature::from_slice(signature_bytes).map_err(|_| ())?;
    key.verify(message, &signature).map_err(|_| ())
}

/// Domain separator for `compute_signing_hash`.
///
/// Prepended to the hash input so that an Ed25519 signature over a Wispers
/// roster signing-hash can never be mistaken for a signature in another
/// protocol that happens to also sign 32-byte SHA-256 outputs. The version
/// suffix lets us evolve the hashing scheme later if needed.
const SIGNING_HASH_DOMAIN: &[u8] = b"wispers-connect/roster-signing/v1\0";

/// Compute the signing hash for the latest addendum in `roster`.
///
/// The hash is the SHA-256 of `SIGNING_HASH_DOMAIN || roster.encode_to_vec()`.
///
/// **Precondition:** the latest addendum's signatures must be empty, since the
/// signers obviously haven't filled them in yet at hashing time. Cosigners
/// (e.g. an endorser receiving a partially-signed roster) must call
/// `clear_latest_addendum_signatures` on a clone first.
///
/// **Determinism note:** this function depends on `prost`'s wire-format
/// encoding being deterministic and on `Vec::new()` for `bytes` fields
/// being equivalent to "field absent" on the wire (which it is for
/// non-`optional` proto3 `bytes`). The `compute_signing_hash_*` tests
/// verify this empirically.
#[must_use]
pub fn compute_signing_hash(roster: &Roster) -> Vec<u8> {
    debug_assert!(
        latest_addendum_signatures_are_empty(roster),
        "compute_signing_hash precondition violated: \
         the latest addendum's signatures must be empty before hashing. \
         Use clear_latest_addendum_signatures on a clone if you need to \
         hash a roster with sigs already filled in."
    );
    let mut hasher = Sha256::new();
    hasher.update(SIGNING_HASH_DOMAIN);
    hasher.update(roster.encode_to_vec());
    hasher.finalize().to_vec()
}

/// Returns true if the latest addendum has empty signature fields.
/// Used as the precondition check for `compute_signing_hash`.
fn latest_addendum_signatures_are_empty(roster: &Roster) -> bool {
    match roster.addenda.last().and_then(|a| a.kind.as_ref()) {
        Some(addendum::Kind::Activation(act)) => {
            act.new_node_signature.is_empty() && act.endorser_signature.is_empty()
        }
        Some(addendum::Kind::Revocation(rev)) => rev.revoker_signature.is_empty(),
        None => true,
    }
}

/// Clear the latest addendum's signatures in place.
///
/// Used by callers (e.g. `serving::roster_cosign`) that hold a roster with
/// signatures already filled in but need an empty-sigs version to compute
/// the signing hash. Typical usage: clone the roster, clear signatures,
/// then call `compute_signing_hash` on the cleared clone.
pub fn clear_latest_addendum_signatures(roster: &mut Roster) {
    if let Some(last) = roster.addenda.last_mut() {
        match last.kind.as_mut() {
            Some(addendum::Kind::Activation(act)) => {
                act.new_node_signature.clear();
                act.endorser_signature.clear();
            }
            Some(addendum::Kind::Revocation(rev)) => {
                rev.revoker_signature.clear();
            }
            None => {}
        }
    }
}

//-- Roster builders -----------------------------------------------------------
//
// These functions create new roster versions. They're used by state.rs for
// activation/revocation and by tests to verify that built rosters pass
// verification.

/// Build an activation payload without signatures, for use with either
/// `create_bootstrap_roster` or `add_activation_to_roster`.
#[must_use]
pub fn build_activation_payload(
    base_roster: &Roster,
    new_node_number: i32,
    endorser_node_number: i32,
    new_node_nonce: Vec<u8>,
    endorser_nonce: Vec<u8>,
) -> roster::activation::Payload {
    roster::activation::Payload {
        version: base_roster.version + 1,
        new_node_number,
        endorser_node_number,
        new_node_nonce,
        endorser_nonce,
    }
}

/// Create a bootstrap roster (version 1) with two founding nodes.
///
/// During bootstrap, both nodes are added simultaneously. The `new_node` signs
/// the roster; the `endorser_signature` is left empty to be filled by the hub
/// after obtaining the endorser's signature.
#[must_use]
pub fn create_bootstrap_roster(
    payload: roster::activation::Payload,
    new_node_pubkey_spki: &[u8],
    endorser_pubkey_spki: &[u8],
) -> Roster {
    debug_assert_eq!(payload.version, 1, "bootstrap payload must have version=1");

    Roster {
        version: 1,
        nodes: vec![
            roster::Node {
                node_number: payload.endorser_node_number,
                public_key_spki: endorser_pubkey_spki.to_vec(),
                revoked: false,
            },
            roster::Node {
                node_number: payload.new_node_number,
                public_key_spki: new_node_pubkey_spki.to_vec(),
                revoked: false,
            },
        ],
        addenda: vec![roster::Addendum {
            kind: Some(addendum::Kind::Activation(roster::Activation {
                payload: Some(payload),
                new_node_signature: Vec::new(),
                endorser_signature: Vec::new(),
            })),
        }],
    }
}

/// Append an activation addendum to `roster`, in place.
///
/// Bumps the version, adds the new node to `roster.nodes`, and pushes an
/// activation addendum with empty signature fields (for the caller to fill in
/// via `set_new_node_signature` / `set_endorser_signature` after computing the
/// signing hash).
pub fn add_activation_to_roster(
    roster: &mut Roster,
    payload: roster::activation::Payload,
    new_node_pubkey_spki: &[u8],
) {
    debug_assert_eq!(
        payload.version,
        roster.version + 1,
        "payload version must be roster.version + 1"
    );

    roster.version = payload.version;
    roster.nodes.push(roster::Node {
        node_number: payload.new_node_number,
        public_key_spki: new_node_pubkey_spki.to_vec(),
        revoked: false,
    });
    roster.addenda.push(roster::Addendum {
        kind: Some(addendum::Kind::Activation(roster::Activation {
            payload: Some(payload),
            new_node_signature: Vec::new(),
            endorser_signature: Vec::new(),
        })),
    });
}

/// Build a revocation payload (intent only — no signature, no hash).
#[must_use]
pub fn build_revocation_payload(
    base_roster: &Roster,
    target_node: i32,
    revoker: i32,
) -> roster::revocation::Payload {
    roster::revocation::Payload {
        version: base_roster.version + 1,
        revoked_node_number: target_node,
        revoker_node_number: revoker,
    }
}

/// Append a revocation addendum to `roster`, in place.
///
/// Bumps the version, marks the revoked node's `revoked` flag in
/// `roster.nodes`, and pushes a revocation addendum with an empty
/// `revoker_signature` (for the caller to fill in via `set_revoker_signature`
/// after computing the signing hash).
pub fn add_revocation_to_roster(roster: &mut Roster, payload: roster::revocation::Payload) {
    debug_assert_eq!(
        payload.version,
        roster.version + 1,
        "payload version must be roster.version + 1"
    );

    roster.version = payload.version;

    if let Some(node) = roster
        .nodes
        .iter_mut()
        .find(|n| n.node_number == payload.revoked_node_number)
    {
        node.revoked = true;
    }

    roster.addenda.push(roster::Addendum {
        kind: Some(addendum::Kind::Revocation(roster::Revocation {
            payload: Some(payload),
            revoker_signature: Vec::new(),
        })),
    });
}

/// Set the new node's signature on the latest addendum (which must be an
/// activation).
///
/// # Panics
///
/// Panics if the roster has no addenda, the addendum has no kind, or it is not an activation.
pub fn set_new_node_signature(roster: &mut Roster, signature: Vec<u8>) {
    let last = roster.addenda.last_mut().expect("roster has no addenda");
    match last.kind.as_mut().expect("addendum has no kind") {
        addendum::Kind::Activation(act) => act.new_node_signature = signature,
        addendum::Kind::Revocation(_) => {
            panic!("set_new_node_signature called on a revocation addendum")
        }
    }
}

/// Set the endorser's signature on the latest addendum (which must be an
/// activation).
///
/// # Panics
///
/// Panics if the roster has no addenda, the addendum has no kind, or it is not an activation.
pub fn set_endorser_signature(roster: &mut Roster, signature: Vec<u8>) {
    let last = roster.addenda.last_mut().expect("roster has no addenda");
    match last.kind.as_mut().expect("addendum has no kind") {
        addendum::Kind::Activation(act) => act.endorser_signature = signature,
        addendum::Kind::Revocation(_) => {
            panic!("set_endorser_signature called on a revocation addendum")
        }
    }
}

/// Set the revoker's signature on the latest addendum (which must be a
/// revocation).
///
/// # Panics
///
/// Panics if the roster has no addenda, the addendum has no kind, or it is not a revocation.
pub fn set_revoker_signature(roster: &mut Roster, signature: Vec<u8>) {
    let last = roster.addenda.last_mut().expect("roster has no addenda");
    match last.kind.as_mut().expect("addendum has no kind") {
        addendum::Kind::Revocation(rev) => rev.revoker_signature = signature,
        addendum::Kind::Activation(_) => {
            panic!("set_revoker_signature called on an activation addendum")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use ed25519_dalek::pkcs8::EncodePublicKey;
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
    /// Uses the public builders so that any future change to the protocol
    /// flows through these helpers automatically.
    fn build_bootstrap_roster(
        key_a: &SigningKey,
        node_a: i32,
        key_b: &SigningKey,
        node_b: i32,
    ) -> Roster {
        // Node B is the "new node" being activated, endorsed by node A.
        let payload = build_activation_payload(
            &Roster::default(),
            node_b,
            node_a,
            b"node_b_nonce".to_vec(),
            b"node_a_nonce".to_vec(),
        );
        let mut roster = create_bootstrap_roster(payload, &spki(key_b), &spki(key_a));
        let signing_hash = compute_signing_hash(&roster);
        set_new_node_signature(&mut roster, sign(key_b, &signing_hash));
        set_endorser_signature(&mut roster, sign(key_a, &signing_hash));
        roster
    }

    /// Add a new node to the roster (activation).
    fn add_node(
        roster: &mut Roster,
        new_key: &SigningKey,
        new_node_number: i32,
        endorser_key: &SigningKey,
        endorser_node_number: i32,
    ) {
        let payload = build_activation_payload(
            roster,
            new_node_number,
            endorser_node_number,
            format!("nonce_{new_node_number}").into_bytes(),
            format!("endorser_nonce_{}", roster.version + 1).into_bytes(),
        );
        add_activation_to_roster(roster, payload, &spki(new_key));
        let signing_hash = compute_signing_hash(roster);
        set_new_node_signature(roster, sign(new_key, &signing_hash));
        set_endorser_signature(roster, sign(endorser_key, &signing_hash));
    }

    /// Revoke a node from the roster.
    fn revoke_node(roster: &mut Roster, target_node: i32, revoker_key: &SigningKey, revoker: i32) {
        let payload = build_revocation_payload(roster, target_node, revoker);
        add_revocation_to_roster(roster, payload);
        let signing_hash = compute_signing_hash(roster);
        set_revoker_signature(roster, sign(revoker_key, &signing_hash));
    }

    // ==================== Basic structure tests ====================

    #[test]
    fn test_invalid_version_zero() {
        let key = generate_key();
        let roster = Roster {
            version: 0,
            nodes: vec![],
            addenda: vec![],
        };
        let result = verify_roster(&roster, 1, &spki(&key));
        assert!(matches!(
            result,
            Err(RosterVerificationError::InvalidVersion(0))
        ));
    }

    #[test]
    fn test_addenda_count_mismatch() {
        let key = generate_key();
        let roster = Roster {
            version: 2,
            nodes: vec![],
            addenda: vec![], // Should have 2 addenda
        };
        let result = verify_roster(&roster, 1, &spki(&key));
        assert!(matches!(
            result,
            Err(RosterVerificationError::AddendaCountMismatch { .. })
        ));
    }

    #[test]
    fn test_duplicate_node_numbers() {
        // Hub injects a duplicate of node 1 into the nodes list of an
        // otherwise-valid roster. The forward walker reconstructs the
        // canonical nodes list from the addenda alone (which has no
        // duplicates), then compares to the tampered input — mismatch.
        let key1 = generate_key();
        let key2 = generate_key();
        let mut roster = build_bootstrap_roster(&key1, 1, &key2, 2);
        roster.nodes.push(roster::Node {
            node_number: 1,
            public_key_spki: spki(&key1),
            revoked: false,
        });

        let result = verify_roster(&roster, 1, &spki(&key1));
        assert!(
            matches!(result, Err(RosterVerificationError::ReconstructionMismatch)),
            "expected ReconstructionMismatch, got {result:?}"
        );
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
            assert!(result.is_ok(), "Node {node_num} should verify successfully");
            let verified_keys = result.unwrap();
            assert_eq!(verified_keys.len(), 4);
        }
    }

    #[test]
    fn test_verification_during_roster_growth() {
        // Similar to Go test: verify at each step of building a roster
        let keys: Vec<_> = (0..5).map(|_| generate_key()).collect();

        // Bootstrap with keys[0] (node 0) and keys[1] (node 1)
        let mut roster = build_bootstrap_roster(&keys[0], 0, &keys[1], 1);

        // After bootstrap, nodes 0 and 1 should verify
        for (j, key) in keys.iter().enumerate() {
            let result = verify_roster(&roster, j as i32, &spki(key));
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
            add_node(
                &mut roster,
                &keys[i],
                i as i32,
                &keys[i - 1],
                (i - 1) as i32,
            );

            // Verify that nodes in the roster can verify, nodes not yet added cannot
            for (j, key) in keys.iter().enumerate() {
                let result = verify_roster(&roster, j as i32, &spki(key));
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

    // ==================== new_version_hash tests ====================

    #[test]
    fn test_corrupted_new_version_hash_rejected() {
        let key1 = generate_key();
        let key2 = generate_key();
        let key3 = generate_key();
        let mut roster = build_bootstrap_roster(&key1, 1, &key2, 2);
        add_node(&mut roster, &key3, 3, &key1, 1);

        // Corrupt the activation of node 3 by tampering with one of its
        // payload fields. The signing hash includes the payload bytes, so
        // any change to the payload makes the signatures fail to verify
        // against the recomputed hash.
        if let Some(addendum::Kind::Activation(ref mut act)) = roster.addenda[1].kind
            && let Some(ref mut payload) = act.payload
        {
            payload.new_node_nonce = b"tampered".to_vec();
        }

        let result = verify_roster(&roster, 1, &spki(&key1));
        let err = result.expect_err("must reject corrupted activation payload");
        assert!(
            matches!(err, RosterVerificationError::InvalidNewNodeSignature(2))
                || matches!(err, RosterVerificationError::InvalidEndorserSignature(2)),
            "expected signature error, got: {err:?}"
        );
    }

    // ==================== Cross-reference tests ====================

    #[test]
    fn test_self_endorsement_rejected() {
        let key1 = generate_key();
        let key2 = generate_key();
        let key3 = generate_key();
        let mut roster = build_bootstrap_roster(&key1, 1, &key2, 2);

        // Build a payload with new_node == endorser (self-endorsement).
        let payload = build_activation_payload(
            &roster,
            3, // new node
            3, // endorser == new node
            b"nonce".to_vec(),
            b"endorser_nonce".to_vec(),
        );
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
                endorser_signature: sign(&key3, &payload_bytes),
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

        // Manually create an addendum claiming endorser node 99 (doesn't exist).
        let payload = roster::activation::Payload {
            version: 2,
            new_node_number: 3,
            endorser_node_number: 99,
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
                endorser_signature: sign(&key1, &payload_bytes),
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
        let verified_keys = result.unwrap();
        assert_eq!(verified_keys.len(), 2);
        assert!(verified_keys.contains_key(&2));
        assert!(verified_keys.contains_key(&3));
        assert!(!verified_keys.contains_key(&1)); // Node 1 was revoked
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

        // Try to have revoked node 1 endorse node 4. This would fail
        // because node 1 is revoked. We bypass the public builder so the
        // resulting addendum is genuinely malformed (a real endorser would
        // refuse to sign).
        let payload = roster::activation::Payload {
            version: roster.version + 1,
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

        // Try to have revoked node 1 revoke node 4. We bypass the public
        // builder so the resulting addendum is genuinely malformed.
        let payload = roster::revocation::Payload {
            version: roster.version + 1,
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
        revoke_node(&mut roster, 1, &keys[2], 2); // v5: revoke node 1
        add_node(&mut roster, &keys[5], 5, &keys[3], 3); // v6: add node 5

        // Verify from each active node's perspective
        for &active_node in &[0, 2, 3, 4, 5] {
            let result = verify_roster(&roster, active_node, &spki(&keys[active_node as usize]));
            assert!(result.is_ok(), "Node {active_node} should verify");

            let verified_keys = result.unwrap();
            assert_eq!(verified_keys.len(), 5); // 6 nodes - 1 revoked = 5 active
            assert!(!verified_keys.contains_key(&1)); // Node 1 was revoked
        }

        // Revoked node 1 should fail to verify
        let result = verify_roster(&roster, 1, &spki(&keys[1]));
        assert!(matches!(
            result,
            Err(RosterVerificationError::VerifierRevoked(1))
        ));
    }

    // ==================== Public builder tests ====================
    // These verify that the public builder functions produce valid rosters.

    #[test]
    fn test_create_bootstrap_roster_verifies() {
        let key_a = generate_key();
        let key_b = generate_key();
        let payload = super::build_activation_payload(
            &Roster::default(),
            2, // new node
            1, // endorser
            b"new_node_nonce".to_vec(),
            b"endorser_nonce".to_vec(),
        );
        let mut roster = super::create_bootstrap_roster(payload, &spki(&key_b), &spki(&key_a));

        let signing_hash = super::compute_signing_hash(&roster);
        super::set_new_node_signature(&mut roster, sign(&key_b, &signing_hash));
        super::set_endorser_signature(&mut roster, sign(&key_a, &signing_hash));

        assert!(verify_roster(&roster, 1, &spki(&key_a)).is_ok());
        assert!(verify_roster(&roster, 2, &spki(&key_b)).is_ok());
    }

    #[test]
    fn test_add_activation_to_roster_verifies() {
        let key_a = generate_key();
        let key_b = generate_key();
        let key_c = generate_key();

        let mut roster = build_bootstrap_roster(&key_a, 1, &key_b, 2);

        let payload = super::build_activation_payload(
            &roster,
            3, // new node
            1, // endorser
            b"new_node_nonce".to_vec(),
            b"endorser_nonce".to_vec(),
        );
        super::add_activation_to_roster(&mut roster, payload, &spki(&key_c));

        let signing_hash = super::compute_signing_hash(&roster);
        super::set_new_node_signature(&mut roster, sign(&key_c, &signing_hash));
        super::set_endorser_signature(&mut roster, sign(&key_a, &signing_hash));

        assert!(verify_roster(&roster, 1, &spki(&key_a)).is_ok());
        assert!(verify_roster(&roster, 3, &spki(&key_c)).is_ok());
    }

    #[test]
    fn test_add_revocation_to_roster_verifies() {
        let key_a = generate_key();
        let key_b = generate_key();
        let key_c = generate_key();

        let mut roster = build_bootstrap_roster(&key_a, 1, &key_b, 2);
        add_node(&mut roster, &key_c, 3, &key_a, 1);

        let revocation_payload = super::build_revocation_payload(&roster, 2, 1);
        super::add_revocation_to_roster(&mut roster, revocation_payload);
        let signing_hash = super::compute_signing_hash(&roster);
        super::set_revoker_signature(&mut roster, sign(&key_a, &signing_hash));

        assert!(verify_roster(&roster, 1, &spki(&key_a)).is_ok());
        assert!(verify_roster(&roster, 3, &spki(&key_c)).is_ok());

        // Revoked node 2 should fail
        assert!(matches!(
            verify_roster(&roster, 2, &spki(&key_b)),
            Err(RosterVerificationError::VerifierRevoked(2))
        ));
    }

    #[test]
    fn test_self_revocation_verifies() {
        let key_a = generate_key();
        let key_b = generate_key();

        let mut roster = build_bootstrap_roster(&key_a, 1, &key_b, 2);

        // Node 2 revokes itself (logout)
        let revocation_payload = super::build_revocation_payload(&roster, 2, 2);
        super::add_revocation_to_roster(&mut roster, revocation_payload);
        let signing_hash = super::compute_signing_hash(&roster);
        super::set_revoker_signature(&mut roster, sign(&key_b, &signing_hash));

        assert!(verify_roster(&roster, 1, &spki(&key_a)).is_ok());
        assert!(matches!(
            verify_roster(&roster, 2, &spki(&key_b)),
            Err(RosterVerificationError::VerifierRevoked(2))
        ));
    }

    // ==================== compute_signing_hash tests ====================

    /// `compute_signing_hash` enforces its precondition with a debug assert.
    /// In debug builds, calling it on a roster with non-empty latest
    /// signatures must panic.
    #[test]
    #[should_panic(expected = "compute_signing_hash precondition violated")]
    #[cfg(debug_assertions)]
    fn compute_signing_hash_panics_on_filled_signatures() {
        let key_a = generate_key();
        let key_b = generate_key();
        // build_bootstrap_roster fills in both signatures.
        let roster = build_bootstrap_roster(&key_a, 1, &key_b, 2);
        let _ = super::compute_signing_hash(&roster);
    }

    /// Golden hash: builds a fully-deterministic multi-addendum roster and
    /// compares its signing hash to a hardcoded value.
    ///
    /// This is a tripwire for proto encoding changes between releases. We rely
    /// on the determinism of prost's wireformat serialisation. If this test
    /// fails, the new version of the code will reject existing rosters and in
    /// turn produce roster signatures that don't verify with older versions of
    /// the library.
    #[test]
    fn golden_signing_hash() {
        use ed25519_dalek::SigningKey;

        // Deterministic signing keys. Ed25519 public keys are a
        // deterministic function of the seed, and ed25519-dalek v2's
        // signing is deterministic per RFC 8032, so the whole test is
        // reproducible.
        let key_a = SigningKey::from_bytes(&[0xAA; 32]);
        let key_b = SigningKey::from_bytes(&[0xBB; 32]);
        let key_c = SigningKey::from_bytes(&[0xCC; 32]);
        let spki_a = spki(&key_a);
        let spki_b = spki(&key_b);
        let spki_c = spki(&key_c);

        // Step 1: bootstrap roster (v1). Node 1 (key_a) endorses node 2 (key_b).
        let payload_v1 = super::build_activation_payload(
            &Roster::default(),
            2, // new node
            1, // endorser
            vec![0x11; 16],
            vec![0x22; 16],
        );
        let mut roster = super::create_bootstrap_roster(payload_v1, &spki_b, &spki_a);
        let hash_v1 = super::compute_signing_hash(&roster);
        assert_eq!(
            hash_v1,
            hex_decode("1cb992c91b76a528e43d0a42d0381c0bdeb3140e864cc9bfe5eaf2d30443f6ae"),
            "v1 bootstrap signing hash has shifted — proto encoding may have changed",
        );

        // Add sigs so we can chain to v2.
        super::set_new_node_signature(&mut roster, sign(&key_b, &hash_v1));
        super::set_endorser_signature(&mut roster, sign(&key_a, &hash_v1));

        // Step 2: v2 activation — add node 3 (key_c), endorsed by node 1.
        let payload_v2 =
            super::build_activation_payload(&roster, 3, 1, vec![0x33; 16], vec![0x44; 16]);
        super::add_activation_to_roster(&mut roster, payload_v2, &spki_c);
        let hash_v2 = super::compute_signing_hash(&roster);
        assert_eq!(
            hash_v2,
            hex_decode("417e8a2abb725bbeeb63a47f14c9a6edc5518cbeeefffa6d0f6fa05d4b5595df"),
            "v2 activation signing hash has shifted",
        );

        super::set_new_node_signature(&mut roster, sign(&key_c, &hash_v2));
        super::set_endorser_signature(&mut roster, sign(&key_a, &hash_v2));

        // Step 3: v3 revocation — node 3 revokes node 2.
        let payload_v3 = super::build_revocation_payload(&roster, 2, 3);
        super::add_revocation_to_roster(&mut roster, payload_v3);
        let hash_v3 = super::compute_signing_hash(&roster);
        assert_eq!(
            hash_v3,
            hex_decode("77aea2c21f8d8993add4b5a0337e67fa3c9e805fea5341d17e6ba657bf4c981a"),
            "v3 revocation signing hash has shifted",
        );
    }

    /// Decode a hex string to a `Vec<u8>`. Used by the golden hash test
    /// so the hardcoded values stay readable.
    fn hex_decode(s: &str) -> Vec<u8> {
        assert!(
            s.len().is_multiple_of(2),
            "hex string must have even length"
        );
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
            .collect()
    }

    // ==================== C-1 regression tests ====================
    //
    // C-1 was: a malicious hub could substitute a hub-controlled key for the
    // endorser entry in a cosigned bootstrap roster. The activation payload
    // signatures only committed to node *numbers*, not to the resulting
    // roster state, so a self-consistent fake roster (fake key in nodes
    // list + signature with matching fake key) would pass plain
    // `verify_roster` and the new node would unknowingly trust the hub as
    // the endorser.
    //
    // The fix: remove the drift between as-designed (which was correct) and
    // as-implemented (which wasn't). Signers sign the entire update roster
    // instead of just the addendum.

    /// Hub takes the new node's submitted bootstrap roster, swaps the
    /// endorser entry in the nodes list to its own key, and produces a
    /// matching cosignature with that fake key. Plain `verify_roster` must
    /// reject because the recomputed signing hash no longer matches the
    /// hash the new node signed.
    #[test]
    fn test_c1_swapped_endorser_in_nodes_list_rejected() {
        let real_endorser_key = generate_key();
        let fake_endorser_key = generate_key();
        let new_node_key = generate_key();

        let mut tampered = build_bootstrap_roster(&real_endorser_key, 1, &new_node_key, 2);

        // Hub swaps the endorser's entry in the nodes list to its fake key.
        tampered.nodes[0].public_key_spki = spki(&fake_endorser_key);

        // Recompute the signing hash for the tampered roster (clearing
        // the addendum's sigs first, as the precondition requires) and
        // produce a fresh endorser signature with the fake key.
        let tampered_hash = {
            let mut for_hash = tampered.clone();
            super::clear_latest_addendum_signatures(&mut for_hash);
            super::compute_signing_hash(&for_hash)
        };
        if let Some(addendum::Kind::Activation(act)) = tampered.addenda[0].kind.as_mut() {
            act.endorser_signature = sign(&fake_endorser_key, &tampered_hash);
        }

        // The new node verifies as itself with its real key. The endorser
        // signature now verifies (fake key signed tampered hash, fake key
        // in nodes list), but the new node signed the *original* hash, not
        // the tampered one — its signature fails.
        let result = verify_roster(&tampered, 2, &spki(&new_node_key));
        assert!(
            matches!(
                result,
                Err(RosterVerificationError::InvalidNewNodeSignature(1))
            ),
            "expected InvalidNewNodeSignature(1), got {result:?}"
        );
    }

    /// Stronger variant: hub fully fabricates a bootstrap roster with its
    /// own keys for both the nodes list AND the signatures. The hub
    /// computes the signing hash over its fake roster and signs it
    /// correctly. But the new node verifies with its REAL key as anchor,
    /// and the verifier detects that the new node's entry doesn't match
    /// the trust anchor.
    #[test]
    fn test_c1_fully_faked_bootstrap_caught_by_verifier_anchor() {
        let real_new_node_key = generate_key();
        let fake_new_node_key = generate_key();
        let fake_endorser_key = generate_key();

        // Hub builds a fake roster where it controls everything.
        let payload = build_activation_payload(
            &Roster::default(),
            2, // new node
            1, // endorser
            b"any".to_vec(),
            b"any".to_vec(),
        );
        let mut fake_roster = create_bootstrap_roster(
            payload,
            &spki(&fake_new_node_key), // ← hub controls "the new node" key
            &spki(&fake_endorser_key),
        );
        let signing_hash = super::compute_signing_hash(&fake_roster);
        super::set_new_node_signature(&mut fake_roster, sign(&fake_new_node_key, &signing_hash));
        super::set_endorser_signature(&mut fake_roster, sign(&fake_endorser_key, &signing_hash));

        // The real new node verifies with its REAL key. The roster has a
        // FAKE key for node 2 (the hub-controlled key). The verifier's
        // own-entry check catches this.
        let result = verify_roster(&fake_roster, 2, &spki(&real_new_node_key));
        assert!(
            matches!(result, Err(RosterVerificationError::VerifierKeyMismatch(2))),
            "expected VerifierKeyMismatch(2), got {result:?}"
        );
    }

    /// Subtler variant: hub returns a roster where the new node's entry
    /// has the REAL new node key (so `VerifierKeyMismatch` doesn't fire) but
    /// the endorser entry is the hub's fake key. The hub computes a valid
    /// signing hash over its fake roster. But the hub doesn't have the
    /// real new node's signing key, so it can't produce a valid
    /// `new_node_signature`.
    #[test]
    fn test_c1_hub_cannot_forge_new_node_signature_for_swap() {
        let fake_endorser_key = generate_key();
        let new_node_key = generate_key();

        // Hub builds a fake bootstrap roster with the real new node key
        // but the fake endorser key.
        let fake_payload = build_activation_payload(
            &Roster::default(),
            2, // new node
            1, // endorser
            b"any".to_vec(),
            b"any".to_vec(),
        );
        let mut fake_roster = create_bootstrap_roster(
            fake_payload,
            &spki(&new_node_key),
            &spki(&fake_endorser_key),
        );
        let signing_hash = super::compute_signing_hash(&fake_roster);

        // Hub doesn't have new_node_key's private key, so it can't produce
        // a valid signature. The best it can do is sign with its own key.
        super::set_new_node_signature(&mut fake_roster, sign(&fake_endorser_key, &signing_hash));
        super::set_endorser_signature(&mut fake_roster, sign(&fake_endorser_key, &signing_hash));

        // Verification: own-entry check passes (real new node key matches),
        // endorser signature verifies (fake key signed hash), but the
        // new_node_signature was forged with the wrong key.
        let result = verify_roster(&fake_roster, 2, &spki(&new_node_key));
        assert!(
            matches!(
                result,
                Err(RosterVerificationError::InvalidNewNodeSignature(1))
            ),
            "expected InvalidNewNodeSignature(1), got {result:?}"
        );
    }

    /// Sanity check that the happy path still works after the changes.
    #[test]
    fn test_c1_legitimate_bootstrap_still_verifies() {
        let endorser_key = generate_key();
        let new_node_key = generate_key();
        let roster = build_bootstrap_roster(&endorser_key, 1, &new_node_key, 2);

        assert!(verify_roster(&roster, 1, &spki(&endorser_key)).is_ok());
        assert!(verify_roster(&roster, 2, &spki(&new_node_key)).is_ok());
    }

    /// Forward-walk-specific regression: hub adds a phantom node entry to
    /// `Roster.nodes` that no addendum mentions. Without the post-walk
    /// reconstruction comparison this would slip through (the per-step
    /// `new_version_hash` checks are over the reconstructed working state,
    /// not the input). With the comparison it's caught as
    /// `ReconstructionMismatch`.
    #[test]
    fn test_forward_walk_rejects_phantom_node_in_input() {
        let key1 = generate_key();
        let key2 = generate_key();
        let mut roster = build_bootstrap_roster(&key1, 1, &key2, 2);

        // Hub injects a phantom node 99 directly into nodes (no addendum
        // for it).
        let phantom_key = generate_key();
        roster.nodes.push(roster::Node {
            node_number: 99,
            public_key_spki: spki(&phantom_key),
            revoked: false,
        });

        let result = verify_roster(&roster, 1, &spki(&key1));
        assert!(
            matches!(result, Err(RosterVerificationError::ReconstructionMismatch)),
            "expected ReconstructionMismatch, got {result:?}"
        );
    }

    /// Forward-walk-specific regression: hub flips a node's `revoked` flag
    /// in the input nodes list without going through a revocation
    /// addendum. Same defence — reconstruction mismatch.
    #[test]
    fn test_forward_walk_rejects_revoked_flag_tampering() {
        let key1 = generate_key();
        let key2 = generate_key();
        let mut roster = build_bootstrap_roster(&key1, 1, &key2, 2);

        // Hub flips node 2's revoked flag.
        roster.nodes[1].revoked = true;

        let result = verify_roster(&roster, 1, &spki(&key1));
        assert!(
            matches!(result, Err(RosterVerificationError::ReconstructionMismatch)),
            "expected ReconstructionMismatch, got {result:?}"
        );
    }
}
