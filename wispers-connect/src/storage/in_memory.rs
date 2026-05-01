use crate::storage::{NodeStateStore, StorageError};
use crate::types::PersistedNodeState;
use std::sync::RwLock;

/// Simple, non-persistent store useful for testing and sketches.
#[derive(Default)]
pub struct InMemoryNodeStateStore {
    state: RwLock<Option<PersistedNodeState>>,
}

impl InMemoryNodeStateStore {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }
}

impl NodeStateStore for InMemoryNodeStateStore {
    fn load(&self) -> Result<Option<PersistedNodeState>, StorageError> {
        let state = self.state.read().map_err(|_| StorageError::Poisoned)?;
        Ok(state.clone())
    }

    fn save(&self, state: &PersistedNodeState) -> Result<(), StorageError> {
        let mut stored = self.state.write().map_err(|_| StorageError::Poisoned)?;
        *stored = Some(state.clone());
        Ok(())
    }

    fn delete(&self) -> Result<(), StorageError> {
        let mut stored = self.state.write().map_err(|_| StorageError::Poisoned)?;
        *stored = None;
        Ok(())
    }
}
