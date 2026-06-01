//! Separate database connection pools for different workloads.
//!
//! This module provides wrapper types for PgPool to allow separate
//! connection pools for agent long-polling operations vs regular API requests.
//! This prevents agent polling from exhausting the connection pool and
//! blocking regular user requests.

use sqlx::{Pool, Postgres};
use std::ops::Deref;

/// Dedicated connection pool for agent operations (long-polling, commands).
/// This pool has higher capacity to handle many concurrent agent connections.
#[derive(Clone, Debug)]
pub struct AgentPgPool(Pool<Postgres>);

impl AgentPgPool {
    pub fn new(pool: Pool<Postgres>) -> Self {
        Self(pool)
    }

    pub fn inner(&self) -> &Pool<Postgres> {
        &self.0
    }
}

impl Deref for AgentPgPool {
    type Target = Pool<Postgres>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<Pool<Postgres>> for AgentPgPool {
    fn as_ref(&self) -> &Pool<Postgres> {
        &self.0
    }
}

/// Type alias for the regular API pool (for clarity in code)
pub type ApiPgPool = Pool<Postgres>;
