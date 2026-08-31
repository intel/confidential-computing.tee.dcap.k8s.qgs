// Copyright(c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

//! CRD type definitions for TdxQuoteGenerationService

use kube::{CustomResource, KubeSchema};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::status::{Condition, ConditionManager};

/// TdxQuoteGenerationService specification
#[derive(CustomResource, KubeSchema, Debug, Clone, Serialize, Deserialize)]
#[kube(
    group = "trustedservices.intel.com",
    version = "v1",
    kind = "TdxQuoteGenerationService",
    plural = "tdxquotegenerationservices",
    singular = "tdx-quote-generation-service",
    shortname = "tqgs",
    scope = "Cluster",
    label("app.kubernetes.io/name", "tdx_quote_generation_service"),
    label("app.kubernetes.io/managed-by", "operator"),
    status = "TdxQuoteGenerationServiceStatus",
    printcolumn = r#"{"name":"Ready","type":"string","jsonPath":".status.conditions[?(@.type==\"Ready\")].status"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#,
    cel,
    validation = Rule::new("self.metadata.name == 'intel-tdx-dcap'")
        .message("Only one TdxQuoteGenerationService is allowed. The resource name must be set to 'intel-tdx-dcap'")
)]
#[serde(rename_all = "camelCase")]
pub struct TdxQuoteGenerationServiceSpec {
    /// Platform registration mode
    #[serde(default = "default_platform_registration")]
    #[x_kube(
        validation = Rule::new("[has(self.Online), has(self.Offline), has(self.External)].filter(mode, mode).size() == 1")
            .message("Exactly one platformRegistration mode must be set: Online, Offline, or External")
    )]
    pub platform_registration: PlatformRegistration,

    /// Node selector labels in "key=value" format to target specific nodes
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(max = 16))]
    pub node_selector: Option<Vec<NodeSelectorEntry>>,
}

/// Online mode configuration
#[derive(Debug, Clone, Serialize, Deserialize, KubeSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
#[x_kube(
    validation = Rule::new("!has(self.apiKeySecretName) || self.apiKeySecretName.matches('^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$')")
        .message("apiKeySecretName must be a valid Kubernetes Secret name")
)]
pub struct OnlineConfig {
    /// Optional secret name containing the Intel API key
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(length(max = 253))]
    pub api_key_secret_name: Option<String>,
}

/// Platform registration mode
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub enum PlatformRegistration {
    /// Online registration with Intel PCS (requires Deployment)
    Online(OnlineConfig),
    /// Offline registration (no Deployment created, platform-registration initContainer runs)
    Offline {},
    /// External registration (no Deployment, no initContainer - PCK Certificate secrets and platform registration managed externally)
    External {},
}

fn default_platform_registration() -> PlatformRegistration {
    PlatformRegistration::Offline {}
}

/// A single node selector entry in "key=value" format
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NodeSelectorEntry(pub String);

impl JsonSchema for NodeSelectorEntry {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "NodeSelectorEntry".into()
    }

    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string",
            "maxLength": 317,
            "x-kubernetes-validations": [{
                "rule": "self.matches('^([A-Za-z0-9][-A-Za-z0-9_.]*/)?[A-Za-z0-9]([-A-Za-z0-9_.]*[A-Za-z0-9])?=.+$')",
                "message": "nodeSelector entries must be in key=value format with a non-empty key and value"
            }]
        })
    }
}

/// TdxQuoteGenerationService status
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "camelCase")]
pub struct TdxQuoteGenerationServiceStatus {
    /// Name of the managed DaemonSet
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub daemonset_name: Option<String>,

    /// Number of nodes that should be running the daemon pod
    #[serde(default)]
    pub desired_number_scheduled: i32,

    /// Number of nodes that are running at least one daemon pod and are supposed to
    #[serde(default)]
    pub current_number_scheduled: i32,

    /// Number of nodes that should be running the daemon pod and have one or more running and ready
    #[serde(default)]
    pub number_ready: i32,

    /// Name of the platform registration Deployment (only when Online mode)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registration_deployment_name: Option<String>,

    /// Whether the registration deployment is ready (only when Online mode)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registration_deployment_ready: Option<bool>,

    /// Status conditions following Kubernetes conventions
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,

    /// The generation most recently observed by the controller
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,
}

impl ConditionManager for TdxQuoteGenerationServiceStatus {
    fn conditions(&self) -> &[Condition] {
        &self.conditions
    }

    fn conditions_mut(&mut self) -> &mut Vec<Condition> {
        &mut self.conditions
    }
}
