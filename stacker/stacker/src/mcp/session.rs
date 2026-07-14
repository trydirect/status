use serde_json::Value;
use std::collections::HashMap;

/// MCP Session state management
#[derive(Debug, Clone)]
pub struct McpSession {
    pub id: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub context: HashMap<String, Value>,
    pub initialized: bool,
}

impl McpSession {
    pub fn new() -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            created_at: chrono::Utc::now(),
            context: HashMap::new(),
            initialized: false,
        }
    }

    /// Store context value
    pub fn set_context(&mut self, key: String, value: Value) {
        self.context.insert(key, value);
    }

    /// Retrieve context value
    pub fn get_context(&self, key: &str) -> Option<&Value> {
        self.context.get(key)
    }

    /// Clear all context
    pub fn clear_context(&mut self) {
        self.context.clear();
    }

    /// Mark session as initialized
    pub fn set_initialized(&mut self, initialized: bool) {
        self.initialized = initialized;
    }

    /// Check if session is initialized
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }
}

impl Default for McpSession {
    fn default() -> Self {
        Self::new()
    }
}
