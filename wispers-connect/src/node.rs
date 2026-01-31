//! Unified node type with runtime state checks.
//!
//! This module provides a single `Node<S>` type that replaces the previous
//! typestate pattern (`PendingNodeState`, `RegisteredNodeState`, `ActivatedNode`).
//! Operations that require a specific stage will return `InvalidState` errors
//! if called in the wrong stage.

use std::fmt;

/// The stage/phase a node is currently in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeStage {
    /// Node needs to register with the hub.
    Pending,
    /// Node is registered but not yet activated.
    Registered,
    /// Node is activated and ready for P2P connections.
    Activated,
}

impl fmt::Display for NodeStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NodeStage::Pending => write!(f, "Pending"),
            NodeStage::Registered => write!(f, "Registered"),
            NodeStage::Activated => write!(f, "Activated"),
        }
    }
}
