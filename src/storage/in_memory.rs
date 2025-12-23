use crate::storage::NodeStateStore;
use crate::types::{AppNamespace, NodeState, ProfileNamespace};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use thiserror::Error;

/// Simple, non-persistent store useful for testing and sketches.
#[derive(Clone, Default)]
pub struct InMemoryNodeStateStore {
    states: Arc<RwLock<HashMap<(AppNamespace, ProfileNamespace), NodeState>>>,
}

impl InMemoryNodeStateStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl NodeStateStore for InMemoryNodeStateStore {
    type Error = InMemoryStoreError;

    fn load(
        &self,
        app_namespace: &AppNamespace,
        profile_namespace: &ProfileNamespace,
    ) -> Result<Option<NodeState>, Self::Error> {
        let states = self
            .states
            .read()
            .map_err(|_| InMemoryStoreError::Poisoned)?;
        Ok(states
            .get(&(app_namespace.clone(), profile_namespace.clone()))
            .cloned())
    }

    fn save(&self, state: &NodeState) -> Result<(), Self::Error> {
        let mut states = self
            .states
            .write()
            .map_err(|_| InMemoryStoreError::Poisoned)?;
        let key = (state.app_namespace.clone(), state.profile_namespace.clone());
        states.insert(key, state.clone());
        Ok(())
    }

    fn delete(
        &self,
        app_namespace: &AppNamespace,
        profile_namespace: &ProfileNamespace,
    ) -> Result<(), Self::Error> {
        let mut states = self
            .states
            .write()
            .map_err(|_| InMemoryStoreError::Poisoned)?;
        states.remove(&(app_namespace.clone(), profile_namespace.clone()));
        Ok(())
    }
}

/// Errors that can arise from the in-memory store (primarily poisoning).
#[derive(Debug, Error)]
pub enum InMemoryStoreError {
    #[error("in-memory state lock was poisoned")]
    Poisoned,
}
