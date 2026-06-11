// Copyright(c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

//! CRD type definitions for TdxQuoteGenerationService

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::status::{Condition, ConditionManager};

/// TdxQuoteGenerationService specification
#[derive(CustomResource, Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "trustedservices.intel.com",
    version = "v1",
    kind = "TdxQuoteGenerationService",
    status = "TdxQuoteGenerationServiceStatus",
    printcolumn = r#"{"name":"Ready","type":"string","jsonPath":".status.conditions[?(@.type==\"Ready\")].status"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct TdxQuoteGenerationServiceSpec {
    /// Platform registration mode
    #[serde(default = "default_platform_registration")]
    pub platform_registration: PlatformRegistration,

    /// Node selector labels in "key=value" format to target specific nodes
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_selector: Option<Vec<String>>,
}

/// Platform registration mode
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub enum PlatformRegistration {
    /// Online registration with Intel PCS (requires Deployment)
    Online {
        /// Optional secret name containing the Intel API key
        #[serde(skip_serializing_if = "Option::is_none", rename = "apiKeySecretName")]
        api_key_secret_name: Option<String>,
    },
    /// Offline registration (no Deployment created, platform-registration initContainer runs)
    Offline {},
    /// External registration (no Deployment, no initContainer - PCK Certificate secrets and platform registration managed externally)
    External {},
}

fn default_platform_registration() -> PlatformRegistration {
    PlatformRegistration::Offline {}
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
