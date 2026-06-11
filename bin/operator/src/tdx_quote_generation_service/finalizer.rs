// Copyright(c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

//! Finalizer helpers for TdxQuoteGenerationService resources
//!
//! This module provides utility functions for managing finalizers on TdxQuoteGenerationService resources.
//! Finalizers ensure that cleanup logic runs before a resource is deleted.

use kube::{
    ResourceExt,
    api::{Api, Patch, PatchParams},
};
use serde_json::json;

use crate::error::{Error, Result};
use crate::tdx_quote_generation_service::types::TdxQuoteGenerationService;

/// Finalizer name for TdxQuoteGenerationService resources
pub use super::controller::FINALIZER;

/// Check if a resource has our finalizer
pub fn has_finalizer(resource: &TdxQuoteGenerationService) -> bool {
    resource
        .metadata
        .finalizers
        .as_ref()
        .map(|f| f.iter().any(|finalizer| finalizer == FINALIZER))
        .unwrap_or(false)
}

/// Check if a resource is being deleted (has deletion timestamp)
pub fn is_deleting(resource: &TdxQuoteGenerationService) -> bool {
    resource.metadata.deletion_timestamp.is_some()
}

/// Add our finalizer to a resource
///
/// This should be called early in reconciliation to ensure cleanup runs on deletion.
pub async fn add_finalizer(
    api: &Api<TdxQuoteGenerationService>,
    name: &str,
) -> Result<TdxQuoteGenerationService> {
    let resource = api.get(name).await.map_err(Error::Kube)?;
    let mut finalizers = resource.metadata.finalizers.clone().unwrap_or_default();

    if finalizers.iter().any(|finalizer| finalizer == FINALIZER) {
        return Ok(resource);
    }

    finalizers.push(FINALIZER.to_string());

    let patch = json!({
        "metadata": {
            "finalizers": finalizers
        }
    });

    api.patch(name, &PatchParams::apply("operator"), &Patch::Merge(&patch))
        .await
        .map_err(Error::Kube)
}

/// Remove our finalizer from a resource
///
/// This should be called after cleanup is complete to allow deletion to proceed.
pub async fn remove_finalizer(
    api: &Api<TdxQuoteGenerationService>,
    name: &str,
) -> Result<TdxQuoteGenerationService> {
    let resource = api.get(name).await.map_err(Error::Kube)?;
    let Some(mut finalizers) = resource.metadata.finalizers.clone() else {
        return Ok(resource);
    };

    let original_len = finalizers.len();
    finalizers.retain(|finalizer| finalizer != FINALIZER);

    if finalizers.len() == original_len {
        return Ok(resource);
    }

    let finalizers = if finalizers.is_empty() {
        json!(null)
    } else {
        json!(finalizers)
    };

    let patch = json!({
        "metadata": {
            "finalizers": finalizers
        }
    });

    api.patch(name, &PatchParams::apply("operator"), &Patch::Merge(&patch))
        .await
        .map_err(Error::Kube)
}

/// Ensure the finalizer is present on a resource
///
/// This is idempotent - if the finalizer is already present, no action is taken.
pub async fn ensure_finalizer(
    api: &Api<TdxQuoteGenerationService>,
    resource: &TdxQuoteGenerationService,
) -> Result<Option<TdxQuoteGenerationService>> {
    if has_finalizer(resource) {
        Ok(None)
    } else {
        add_finalizer(api, &resource.name_any()).await.map(Some)
    }
}
