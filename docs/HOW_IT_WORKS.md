# How it works

This document explains the design of Wispers Connect: how nodes find each
other, how they establish trust, and how data moves between them.

## Architecture overview

<!-- TODO: diagram (mermaid) showing Hub, nodes, coturn, and the
     distinction between signaling (through Hub) and data (P2P).
     Source material: connect/DESIGN.md "Components" section. -->

## Node lifecycle

<!-- TODO: state diagram (mermaid) showing Pending -> Registered -> Activated.
     Explain what each state means and what operations are available.
     Source material: ARCHITECTURE.md "Node State Machine" section. -->

## Registration

<!-- TODO: explain the integrator-driven registration flow.
     Token creation via REST API, OTP handoff to the node, completing
     registration with the Hub.
     Source material: connect/DESIGN.md "Node registration through an
     integrator" section. -->

## Activation & the roster

<!-- TODO: this is the core of the trust model. Cover:
     - What the roster is (protobuf with public keys, co-signed addenda)
     - Pairing: out-of-band secret, HMAC-based key exchange through Hub
     - Roster update: new node creates roster version, endorser co-signs
     - Bootstrap: first two nodes pair to create the initial roster
     - Transitive trust: every node trusts all others through the chain
     Source material: connect/DESIGN.md "Activation" section.
     Consider a mermaid sequence diagram for the pairing flow. -->

## Revocation

<!-- TODO: explain how any activated node can revoke any other.
     Cover the security trade-offs (single-revoker matches single-endorser).
     Source material: connect/DESIGN.md "Revocation" section. -->

## Peer-to-peer connections

<!-- TODO: explain connection setup. Cover:
     - ICE/STUN/TURN for NAT traversal (libjuice)
     - Signaling through the Hub (StartConnectionRequest/Response)
     - X25519 key exchange for forward secrecy
     - Signature verification against the roster
     Source material: connect/DESIGN.md "Peer-to-peer connection setup"
     and ARCHITECTURE.md "P2P Transport Architecture". -->

### UDP transport

<!-- TODO: raw UDP with AES-GCM encryption. When to use it
     (low-latency, loss-tolerant).
     Source material: ARCHITECTURE.md "Transport Types" table. -->

### QUIC transport

<!-- TODO: reliable multiplexed streams over the ICE-established UDP path.
     TLS 1.3 PSK authentication (no certificates). When to use it.
     Source material: connect/DESIGN.md "QUIC setup" and
     ARCHITECTURE.md "QUIC Authentication". -->

## Security properties

<!-- TODO: summarise the security guarantees:
     - End-to-end encryption (Hub cannot read data)
     - Roster-based trust (Hub cannot inject nodes)
     - Forward secrecy via ephemeral X25519 keys
     - Out-of-band activation codes (Hub never sees the secret)
     Also cover the known limitations:
     - Compromised node can endorse malicious nodes
     - Compromised node can revoke legitimate nodes (DoS)
     Source material: connect/DESIGN.md "Security Considerations". -->
