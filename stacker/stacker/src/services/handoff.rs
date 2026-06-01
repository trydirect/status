use crate::handoff::DeploymentHandoffPayload;
use chrono::Utc;
use rand::{distributions::Alphanumeric, Rng};
use std::collections::HashMap;
use std::sync::RwLock;

pub struct InMemoryHandoffStore {
    entries: RwLock<HashMap<String, DeploymentHandoffPayload>>,
}

impl InMemoryHandoffStore {
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
        }
    }

    pub fn insert(&self, payload: DeploymentHandoffPayload) -> String {
        self.prune_expired();
        let token = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(40)
            .map(char::from)
            .collect::<String>();
        self.entries
            .write()
            .expect("handoff store poisoned")
            .insert(token.clone(), payload);
        token
    }

    pub fn resolve_once(&self, token: &str) -> Option<DeploymentHandoffPayload> {
        self.prune_expired();
        let payload = self
            .entries
            .write()
            .expect("handoff store poisoned")
            .remove(token)?;
        if payload.expires_at <= Utc::now() {
            return None;
        }
        Some(payload)
    }

    fn prune_expired(&self) {
        let now = Utc::now();
        self.entries
            .write()
            .expect("handoff store poisoned")
            .retain(|_, payload| payload.expires_at > now);
    }
}

impl Default for InMemoryHandoffStore {
    fn default() -> Self {
        Self::new()
    }
}
