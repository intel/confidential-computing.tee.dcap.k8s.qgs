// Copyright(c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

//! Controller for TdxQuoteGenerationService resources
//!
//! This module implements the reconciliation loop for TdxQuoteGenerationService custom resources.
//! The reconciler handles create, update, and delete events with proper error
//! handling, status updates, and requeue logic.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use futures::StreamExt;
use k8s_openapi::api::apps::v1::{DaemonSet, Deployment};
use k8s_openapi::api::core::v1::{EnvVar, EnvVarSource, SecretKeySelector};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference;
use kube::{
    ResourceExt,
    api::{Api, Patch, PatchParams},
    client::Client,
    runtime::{
        controller::{Action, Controller},
        finalizer::{Event as FinalizerEvent, finalizer},
        watcher,
    },
};
use serde_json::json;
use tracing::{debug, error, info, instrument, warn};

use crate::error::{Error, Result};
use crate::tdx_quote_generation_service::{
    ConditionStatus, OnlineConfig, PlatformRegistration, TdxQuoteGenerationService,
};

/// DaemonSet template embedded at compile time
const DAEMONSET_TEMPLATE: &str = include_str!("../../templates/daemonset.yaml");

/// Deployment template embedded at compile time
const DEPLOYMENT_TEMPLATE: &str = include_str!("../../templates/deployment.yaml");

/// Finalizer name for TdxQuoteGenerationService resources
pub const FINALIZER: &str = "trustedservices.intel.com/tdx_quote_generation_service-finalizer";

/// Default requeue interval for successful reconciliations
const DEFAULT_REQUEUE_INTERVAL: Duration = Duration::from_secs(300);

/// Requeue interval after an error
const ERROR_REQUEUE_INTERVAL: Duration = Duration::from_secs(60);

/// Short requeue interval for resources being deleted
const DELETE_REQUEUE_INTERVAL: Duration = Duration::from_secs(5);

/// Context for the TdxQuoteGenerationService controller
pub struct Context {
    /// Kubernetes client
    pub client: Client,
}

/// Reconcile a TdxQuoteGenerationService resource
///
/// This function is called whenever a TdxQuoteGenerationService resource is created, updated, or deleted.
/// It uses finalizers to ensure proper cleanup of external resources.
#[instrument(skip(ctx, resource), fields(name = %resource.name_any()))]
async fn reconcile(resource: Arc<TdxQuoteGenerationService>, ctx: Arc<Context>) -> Result<Action> {
    let name = resource.name_any();

    debug!(
        "Starting reconciliation for TdxQuoteGenerationService {}",
        name
    );

    let api: Api<TdxQuoteGenerationService> = Api::all(ctx.client.clone());

    // Use finalizer to handle cleanup on deletion
    finalizer(&api, FINALIZER, resource, |event| async {
        match event {
            FinalizerEvent::Apply(resource) => reconcile_resource(&resource, &ctx, &api).await,
            FinalizerEvent::Cleanup(resource) => cleanup_resource(&resource, &ctx).await,
        }
    })
    .await
    .map_err(|e| Error::Finalizer(Box::new(e)))
}

/// Reconcile a TdxQuoteGenerationService resource (apply phase)
///
/// This is called for create and update events.
async fn reconcile_resource(
    resource: &TdxQuoteGenerationService,
    ctx: &Context,
    api: &Api<TdxQuoteGenerationService>,
) -> Result<Action> {
    let name = resource.name_any();

    info!("Reconciling TdxQuoteGenerationService {}", name);

    // Ensure only one instance exists
    let all_instances: Api<TdxQuoteGenerationService> = Api::all(ctx.client.clone());
    let instances = all_instances.list(&Default::default()).await?;

    if instances.items.len() > 1 {
        // Find if this is the oldest instance
        let mut sorted_instances = instances.items.clone();
        sorted_instances.sort_by_key(|i| i.metadata.creation_timestamp.clone());

        if let Some(oldest) = sorted_instances.first()
            && oldest.name_any() != name
        {
            warn!(
                "Multiple TdxQuoteGenerationService instances detected. Only '{}' will be reconciled.",
                oldest.name_any()
            );
            update_status(
                    api,
                    &name,
                    "Ready",
                    "False",
                    "MultipleInstances",
                    &format!("Only one TdxQuoteGenerationService instance is allowed. Instance '{}' is active.", oldest.name_any()),
                    resource.metadata.generation,
                ).await?;
            return Ok(Action::requeue(DEFAULT_REQUEUE_INTERVAL));
        }
    }

    // Get namespace from environment variable (operator runs in this namespace)
    let namespace = std::env::var("OPERATOR_NAMESPACE").unwrap_or_else(|_| "default".to_string());
    info!("Using namespace: {}", namespace);

    // Create or update DaemonSet
    let daemonset_name = create_or_update_daemonset(ctx, resource, &namespace).await?;

    // Create or update Deployment if Online registration is configured
    let (deployment_name, deployment_ready) = if matches!(
        &resource.spec.platform_registration,
        PlatformRegistration::Online(_)
    ) {
        let deployment_name = create_or_update_deployment(ctx, resource, &namespace).await?;

        // Get Deployment status
        let deploy_api: Api<Deployment> = Api::namespaced(ctx.client.clone(), &namespace);

        match deploy_api.get(&deployment_name).await {
            Ok(deploy) => {
                let deploy_status = deploy.status.as_ref();
                let ready_replicas = deploy_status.and_then(|s| s.ready_replicas);
                let replicas = deploy_status.and_then(|s| s.replicas);

                let is_deploy_ready = ready_replicas
                    .zip(replicas)
                    .map(|(ready, total)| ready == total && ready > 0)
                    .unwrap_or(false);
                (Some(deployment_name), Some(is_deploy_ready))
            }
            Err(e) => {
                warn!("Failed to get Deployment status: {}", e);
                (Some(deployment_name), Some(false))
            }
        }
    } else {
        // Delete deployment if it exists and we're in Offline mode
        delete_deployment_if_exists(ctx, resource, &namespace).await?;
        (None, None)
    };

    // Get DaemonSet status
    let ds_api: Api<DaemonSet> = Api::namespaced(ctx.client.clone(), &namespace);
    let ds = ds_api.get(&daemonset_name).await?;
    let ds_status = ds.status.as_ref();

    // Determine DaemonSet readiness
    let ds_ready = ds_status
        .map(|s| {
            let desired = s.desired_number_scheduled;
            let ready = s.number_ready;
            desired > 0 && ready == desired
        })
        .unwrap_or(false);

    // Overall readiness includes both DaemonSet and Deployment (if Online mode)
    let is_ready = ds_ready && deployment_ready.unwrap_or(true);

    let desired_count = ds_status.map(|s| s.desired_number_scheduled).unwrap_or(0);
    let current_count = ds_status.map(|s| s.current_number_scheduled).unwrap_or(0);
    let ready_count = ds_status.map(|s| s.number_ready).unwrap_or(0);

    // Only update status if something has changed
    let status_changed = resource.status.as_ref().is_none_or(|s| {
        s.daemonset_name.as_deref() != Some(&daemonset_name)
            || s.desired_number_scheduled != desired_count
            || s.current_number_scheduled != current_count
            || s.number_ready != ready_count
            || s.registration_deployment_name != deployment_name
            || s.registration_deployment_ready != deployment_ready
            || s.observed_generation != resource.metadata.generation
    });

    let ready_condition_changed = resource.status.as_ref().is_none_or(|s| {
        !s.conditions.iter().any(|c| {
            c.condition_type == "Ready"
                && c.status
                    == if is_ready {
                        ConditionStatus::True
                    } else {
                        ConditionStatus::False
                    }
                && c.reason.as_deref()
                    == Some(if is_ready {
                        "ServicesReady"
                    } else {
                        "ServicesNotReady"
                    })
        })
    });

    // Update status if either status fields or condition changed
    if status_changed || ready_condition_changed {
        let message = if is_ready {
            if deployment_ready.is_some() {
                "DaemonSet and registration Deployment are ready"
            } else {
                "DaemonSet is ready and running on all nodes"
            }
        } else if deployment_ready == Some(false) {
            "Registration Deployment is not yet ready"
        } else {
            "DaemonSet is not yet ready on all nodes"
        };

        let condition = json!({
            "type": "Ready",
            "status": if is_ready { "True" } else { "False" },
            "reason": if is_ready { "ServicesReady" } else { "ServicesNotReady" },
            "message": message,
            "lastTransitionTime": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Nanos, true),
            "observedGeneration": resource.metadata.generation,
        });

        let status_patch = json!({
            "status": {
                "daemonsetName": daemonset_name,
                "desiredNumberScheduled": desired_count,
                "currentNumberScheduled": current_count,
                "numberReady": ready_count,
                "registrationDeploymentName": deployment_name,
                "registrationDeploymentReady": deployment_ready,
                "observedGeneration": resource.metadata.generation,
                "conditions": [condition],
            }
        });

        api.patch_status(&name, &PatchParams::default(), &Patch::Merge(&status_patch))
            .await?;
    }

    debug!("Successfully reconciled TdxQuoteGenerationService {}", name);

    // Requeue sooner if resources are not ready yet
    let requeue_interval = if is_ready {
        DEFAULT_REQUEUE_INTERVAL
    } else {
        Duration::from_secs(10) // Check every 10 seconds when not ready
    };

    Ok(Action::requeue(requeue_interval))
}

/// Cleanup resources when a TdxQuoteGenerationService is deleted
///
/// This is called when the resource has a deletion timestamp and we need
/// to clean up any external resources before removing the finalizer.
async fn cleanup_resource(resource: &TdxQuoteGenerationService, ctx: &Context) -> Result<Action> {
    let namespace = std::env::var("OPERATOR_NAMESPACE").unwrap_or_else(|_| "default".to_string());
    info!(
        "Cleaning up resources for TdxQuoteGenerationService {} in namespace {}",
        resource.name_any(),
        namespace
    );

    // Delete DaemonSet
    let ds_api: Api<DaemonSet> = Api::namespaced(ctx.client.clone(), &namespace);
    let daemonset_name = format!("{}-qgs", resource.name_any());
    if let Err(e) = ds_api.delete(&daemonset_name, &Default::default()).await {
        if !is_not_found(&e) {
            error!("Failed to delete DaemonSet {}: {}", daemonset_name, e);
            return Err(Error::Kube(e));
        }
    } else {
        info!("Deleted DaemonSet {}", daemonset_name);
    }

    // Delete Deployment if it exists
    delete_deployment_if_exists(ctx, resource, &namespace).await?;

    info!(
        "Cleanup completed for TdxQuoteGenerationService {}",
        resource.name_any()
    );
    Ok(Action::await_change())
}

/// Helper to check if an error is a NotFound error
fn is_not_found(error: &kube::Error) -> bool {
    matches!(error, kube::Error::Api(api_err) if api_err.code == 404)
}

/// Create an OwnerReference for resources managed by the CR
fn create_owner_reference(resource: &TdxQuoteGenerationService) -> Result<OwnerReference> {
    let uid = resource.metadata.uid.as_ref().ok_or_else(|| {
        Error::Generic("Resource UID is missing - cannot create ownerReference".to_string())
    })?;

    Ok(OwnerReference {
        api_version: "trustedservices.intel.com/v1".to_string(),
        kind: "TdxQuoteGenerationService".to_string(),
        name: resource.name_any(),
        uid: uid.clone(),
        controller: Some(true),
        block_owner_deletion: Some(true),
    })
}

/// Parse node selector strings in "key=value" format into a BTreeMap
fn parse_node_selectors(node_selectors: &[String]) -> Result<BTreeMap<String, String>> {
    let mut map = BTreeMap::new();

    for selector in node_selectors {
        let (key, value) = selector.split_once('=').ok_or_else(|| {
            Error::Generic(format!(
                "Invalid node selector format: '{selector}'. Expected 'key=value'"
            ))
        })?;

        let key = key.trim();
        let value = value.trim();

        if key.is_empty() || value.is_empty() {
            return Err(Error::Generic(format!(
                "Invalid node selector format: '{selector}'. Key and value must be non-empty"
            )));
        }

        if map.insert(key.to_string(), value.to_string()).is_some() {
            return Err(Error::Generic(format!(
                "Duplicate node selector key: '{key}'"
            )));
        }
    }

    Ok(map)
}

/// Create or update DaemonSet
async fn create_or_update_daemonset(
    ctx: &Context,
    resource: &TdxQuoteGenerationService,
    namespace: &str,
) -> Result<String> {
    let ds_api: Api<DaemonSet> = Api::namespaced(ctx.client.clone(), namespace);
    let spec = &resource.spec;
    let daemonset_name = format!("{}-qgs", resource.name_any());

    // Load and parse the DaemonSet template
    let mut ds: DaemonSet = serde_yaml::from_str(DAEMONSET_TEMPLATE)
        .map_err(|e| Error::Generic(format!("Failed to parse DaemonSet template: {e}")))?;

    // Set metadata
    ds.metadata.name = Some(daemonset_name.clone());
    ds.metadata.namespace = Some(namespace.to_string());
    ds.metadata.owner_references = Some(vec![create_owner_reference(resource)?]);

    // Get mutable reference to pod spec
    let pod_spec = ds
        .spec
        .as_mut()
        .and_then(|s| s.template.spec.as_mut())
        .ok_or_else(|| Error::Generic("DaemonSet template missing pod spec".to_string()))?;

    pod_spec.service_account_name = Some(
        std::env::var("QGS_SERVICE_ACCOUNT").unwrap_or_else(|_| "intel-tdx-dcap-qgs".to_string()),
    );

    // Remove platform-registration initContainer and efivars volume for External mode
    if matches!(
        spec.platform_registration,
        PlatformRegistration::External {}
    ) {
        // Remove platform-registration initContainer
        if let Some(ref mut init_containers) = pod_spec.init_containers {
            init_containers.retain(|c| c.name != "platform-registration");
        }

        // Remove efivars volume
        if let Some(ref mut volumes) = pod_spec.volumes {
            volumes.retain(|v| v.name != "efivars");
        }

        info!("Removed platform-registration initContainer and efivars volume (External mode)");
    }

    // Apply node selector if provided
    if let Some(ref selectors) = spec.node_selector {
        let strings: Vec<String> = selectors.iter().map(|e| e.0.clone()).collect();
        pod_spec.node_selector = Some(parse_node_selectors(&strings)?);
    }

    // Override all container images from RELATED_IMAGE_QGS env if set
    if let Some(image) = image_from_env() {
        for c in pod_spec.containers.iter_mut() {
            c.image = Some(image.clone());
        }
        if let Some(ref mut inits) = pod_spec.init_containers {
            for c in inits.iter_mut() {
                c.image = Some(image.clone());
            }
        }
    }

    // Apply the DaemonSet
    ds_api
        .patch(
            &daemonset_name,
            &PatchParams::apply("tdx-qgs-operator"),
            &Patch::Apply(&ds),
        )
        .await?;

    Ok(daemonset_name)
}

/// Create or update Deployment for online platform registration
async fn create_or_update_deployment(
    ctx: &Context,
    resource: &TdxQuoteGenerationService,
    namespace: &str,
) -> Result<String> {
    let deploy_api: Api<Deployment> = Api::namespaced(ctx.client.clone(), namespace);
    let deployment_name = format!("{}-registrar", resource.name_any());

    // Load and parse the Deployment template
    let mut deploy: Deployment = serde_yaml::from_str(DEPLOYMENT_TEMPLATE)
        .map_err(|e| Error::Generic(format!("Failed to parse Deployment template: {e}")))?;

    // Set metadata
    deploy.metadata.name = Some(deployment_name.clone());
    deploy.metadata.namespace = Some(namespace.to_string());
    deploy.metadata.owner_references = Some(vec![create_owner_reference(resource)?]);

    // Get mutable reference to pod spec
    let pod_spec = deploy
        .spec
        .as_mut()
        .and_then(|s| s.template.spec.as_mut())
        .ok_or_else(|| Error::Generic("Deployment template missing pod spec".to_string()))?;

    pod_spec.service_account_name = Some(
        std::env::var("QGS_SERVICE_ACCOUNT").unwrap_or_else(|_| "intel-tdx-dcap-qgs".to_string()),
    );

    // Get the container
    let container = pod_spec
        .containers
        .first_mut()
        .ok_or_else(|| Error::Generic("Deployment template missing container".to_string()))?;

    // If the CR specifies a custom API key secret name, override the default from the template
    if let PlatformRegistration::Online(OnlineConfig {
        api_key_secret_name: Some(secret_name),
        ..
    }) = &resource.spec.platform_registration
    {
        let env = container.env.get_or_insert_with(Vec::new);
        let api_key_env = EnvVar {
            name: "INTEL_PCS_API_KEY".to_string(),
            value: None,
            value_from: Some(EnvVarSource {
                secret_key_ref: Some(SecretKeySelector {
                    name: secret_name.clone(),
                    key: "api-key".to_string(),
                    optional: Some(true),
                }),
                ..Default::default()
            }),
        };

        if let Some(env_var) = env.iter_mut().find(|e| e.name == "INTEL_PCS_API_KEY") {
            *env_var = api_key_env;
        } else {
            env.push(api_key_env);
        }
    }

    // Propagate HTTPS proxy from the operator process environment if set
    for var in ["HTTPS_PROXY", "https_proxy"] {
        if let Ok(value) = std::env::var(var) {
            let env = container.env.get_or_insert_with(Vec::new);
            if !env.iter().any(|e| e.name == var) {
                env.push(k8s_openapi::api::core::v1::EnvVar {
                    name: var.to_string(),
                    value: Some(value),
                    ..Default::default()
                });
            }
        }
    }

    // Override container image from RELATED_IMAGE_QGS env if set
    if let Some(image) = image_from_env() {
        container.image = Some(image);
    }

    // Apply the Deployment
    deploy_api
        .patch(
            &deployment_name,
            &PatchParams::apply("tdx-qgs-operator"),
            &Patch::Apply(&deploy),
        )
        .await?;

    Ok(deployment_name)
}

/// Returns the operand QGS image to use. Follows the OLM RELATED_IMAGE_* convention
/// so operator-sdk automatically includes it in relatedImages when generating the bundle.
fn image_from_env() -> Option<String> {
    std::env::var("RELATED_IMAGE_QGS").ok()
}

/// Delete deployment if it exists
async fn delete_deployment_if_exists(
    ctx: &Context,
    resource: &TdxQuoteGenerationService,
    namespace: &str,
) -> Result<()> {
    let deploy_api: Api<Deployment> = Api::namespaced(ctx.client.clone(), namespace);
    let deployment_name = format!("{}-registrar", resource.name_any());

    if let Err(e) = deploy_api
        .delete(&deployment_name, &Default::default())
        .await
    {
        if is_not_found(&e) {
            return Ok(());
        }

        return Err(Error::Kube(e));
    }

    Ok(())
}

/// Update the status of a TdxQuoteGenerationService resource with a condition
async fn update_status(
    api: &Api<TdxQuoteGenerationService>,
    name: &str,
    condition_type: &str,
    status: &str,
    reason: &str,
    message: &str,
    observed_generation: Option<i64>,
) -> Result<()> {
    let now = Utc::now().to_rfc3339();
    let status_patch = json!({
        "status": {
            "conditions": [{
                "type": condition_type,
                "status": status,
                "reason": reason,
                "message": message,
                "lastTransitionTime": now,
                "observedGeneration": observed_generation
            }],
            "observedGeneration": observed_generation
        }
    });

    api.patch_status(
        name,
        &PatchParams::apply("operator"),
        &Patch::Merge(&status_patch),
    )
    .await
    .map_err(Error::Kube)?;

    Ok(())
}

/// Handle errors during reconciliation
///
/// This function determines the requeue strategy based on the error type.
fn error_policy(
    resource: Arc<TdxQuoteGenerationService>,
    error: &Error,
    _ctx: Arc<Context>,
) -> Action {
    let name = resource.name_any();

    // Log error with appropriate level based on error type
    match error {
        Error::Kube(e) => {
            error!(
                name = %name,
                error = %e,
                "Kubernetes API error during reconciliation"
            );
        }
        Error::Finalizer(e) => {
            warn!(
                name = %name,
                error = ?e,
                "Finalizer error during reconciliation"
            );
        }
        _ => {
            error!(
                name = %name,
                error = ?error,
                "Reconciliation error"
            );
        }
    }

    // Determine requeue interval based on deletion state
    if resource.metadata.deletion_timestamp.is_some() {
        // Resource is being deleted, retry more frequently
        Action::requeue(DELETE_REQUEUE_INTERVAL)
    } else {
        Action::requeue(ERROR_REQUEUE_INTERVAL)
    }
}

/// Start the TdxQuoteGenerationService controller
///
/// This sets up the controller with the watcher configuration and starts
/// the reconciliation loop.
pub async fn run(client: Client) -> Result<()> {
    let api: Api<TdxQuoteGenerationService> = Api::all(client.clone());
    let ctx = Arc::new(Context { client });

    info!("Starting TdxQuoteGenerationService controller");

    Controller::new(api, watcher::Config::default())
        .run(reconcile, error_policy, ctx)
        .for_each(|res| async move {
            match res {
                Ok(o) => debug!("Reconciled {:?}", o),
                Err(e) => error!("Reconcile failed: {:?}", e),
            }
        })
        .await;

    Ok(())
}
