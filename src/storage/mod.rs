use crate::types::{AppNamespace, NodeState, ProfileNamespace};
use std::sync::Arc;

pub mod foreign;
pub mod in_memory;

pub use foreign::{ForeignNodeStateStore, ForeignStoreError, WispersNodeStateStoreCallbacks};
pub use in_memory::{InMemoryNodeStateStore, InMemoryStoreError};

pub trait NodeStateStore: Send + Sync + 'static {
    type Error;

    fn load(
        &self,
        app_namespace: &AppNamespace,
        profile_namespace: &ProfileNamespace,
    ) -> Result<Option<NodeState>, Self::Error>;

    fn save(&self, state: &NodeState) -> Result<(), Self::Error>;

    fn delete(
        &self,
        app_namespace: &AppNamespace,
        profile_namespace: &ProfileNamespace,
    ) -> Result<(), Self::Error>;
}

pub(crate) type SharedStore<S> = Arc<S>;
