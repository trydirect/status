use serde::Serialize;

pub const RUNTIME_ENV_CONTRACT_VERSION: &str = "v1";
pub const RUNTIME_ENV_PRECEDENCE_ORDER: &str = "lowest_to_highest";

pub const RUNTIME_ENV_LAYER_BASE: &str = "base";
pub const RUNTIME_ENV_LAYER_SERVER: &str = "server";
pub const RUNTIME_ENV_LAYER_SERVICE: &str = "service";
pub const RUNTIME_ENV_LAYER_COMPOSE: &str = "compose";

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub struct RuntimeEnvLayerContract {
    pub name: &'static str,
    pub precedence: u8,
    #[serde(rename = "appliesWhen")]
    pub applies_when: &'static str,
    pub description: &'static str,
}

pub const RUNTIME_ENV_LAYER_CONTRACTS: [RuntimeEnvLayerContract; 4] = [
    RuntimeEnvLayerContract {
        name: RUNTIME_ENV_LAYER_BASE,
        precedence: 1,
        applies_when: "Always",
        description: "App env and local authoring inputs provide the base runtime layer.",
    },
    RuntimeEnvLayerContract {
        name: RUNTIME_ENV_LAYER_SERVER,
        precedence: 2,
        applies_when: "Only when inherit_server_secrets=true",
        description: "Server-scope secrets overlay the base layer when the target opts in.",
    },
    RuntimeEnvLayerContract {
        name: RUNTIME_ENV_LAYER_SERVICE,
        precedence: 3,
        applies_when: "When remote service secrets exist for the selected service/app target",
        description: "Service-scope secrets override lower layers for the selected target.",
    },
    RuntimeEnvLayerContract {
        name: RUNTIME_ENV_LAYER_COMPOSE,
        precedence: 4,
        applies_when: "When the compose service defines environment: keys",
        description: "Compose environment keys win over env_file-derived layers at runtime.",
    },
];

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RuntimeEnvContractResponse {
    pub version: &'static str,
    pub order: &'static str,
    pub layers: Vec<RuntimeEnvLayerContract>,
}

pub fn runtime_env_contract_response() -> RuntimeEnvContractResponse {
    RuntimeEnvContractResponse {
        version: RUNTIME_ENV_CONTRACT_VERSION,
        order: RUNTIME_ENV_PRECEDENCE_ORDER,
        layers: RUNTIME_ENV_LAYER_CONTRACTS.to_vec(),
    }
}

pub fn runtime_env_layer_names() -> Vec<&'static str> {
    RUNTIME_ENV_LAYER_CONTRACTS
        .iter()
        .map(|layer| layer.name)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        runtime_env_contract_response, runtime_env_layer_names, RUNTIME_ENV_CONTRACT_VERSION,
        RUNTIME_ENV_LAYER_BASE, RUNTIME_ENV_LAYER_COMPOSE, RUNTIME_ENV_LAYER_SERVER,
        RUNTIME_ENV_LAYER_SERVICE, RUNTIME_ENV_PRECEDENCE_ORDER,
    };

    #[test]
    fn runtime_env_contract_is_stable() {
        let contract = runtime_env_contract_response();

        assert_eq!(contract.version, RUNTIME_ENV_CONTRACT_VERSION);
        assert_eq!(contract.order, RUNTIME_ENV_PRECEDENCE_ORDER);
        assert_eq!(
            runtime_env_layer_names(),
            vec![
                RUNTIME_ENV_LAYER_BASE,
                RUNTIME_ENV_LAYER_SERVER,
                RUNTIME_ENV_LAYER_SERVICE,
                RUNTIME_ENV_LAYER_COMPOSE,
            ]
        );
        assert_eq!(contract.layers.len(), 4);
        assert_eq!(contract.layers[0].precedence, 1);
        assert_eq!(contract.layers[3].precedence, 4);
    }
}
