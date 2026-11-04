// Copyright(c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

use crate::pck_secret::{
    CreatePckSecretInput, pck_secret_manifest, pck_secret_name, piid_index_secret_manifest,
};
use crate::pcs_client::{PckCertsRequest, build_pcs_http_client, fetch_platform_cache};
use crate::platform_data::registration_fingerprint;
use anyhow::{Context, bail};
use k8s_openapi::api::core::v1::Secret;
use kube::api::ListParams;
use kube::{Api, Client};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{info, instrument, warn};

#[derive(Deserialize, Serialize, Debug)]
pub struct PlatformListEntry {
    pub qe_id: String,
    pub pce_id: String,
    pub cpu_svn: String,
    pub platform_manifest: String,
}

impl From<&PlatformListEntry> for PckCertsRequest {
    fn from(platform: &PlatformListEntry) -> Self {
        Self {
            platform_manifest: platform.platform_manifest.clone(),
            pce_id: platform.pce_id.clone(),
            cpu_svn: platform.cpu_svn.clone(),
        }
    }
}

#[instrument(fields(namespace = %namespace, selector = %selector))]
async fn read_platforms_from_secrets(
    namespace: &str,
    selector: &str,
) -> anyhow::Result<Vec<PlatformListEntry>> {
    let client = Client::try_default().await?;
    let secrets: Api<Secret> = Api::namespaced(client, namespace);

    let lp = ListParams::default().labels(selector);
    let listed = secrets.list(&lp).await?;

    let mut platforms = Vec::new();
    for secret in listed.items {
        match platform_entry_from_secret(&secret) {
            Ok(entry) => platforms.push(entry),
            Err(e) => {
                let name = secret
                    .metadata
                    .name
                    .clone()
                    .unwrap_or_else(|| "<unknown>".to_string());
                warn!(secret = %name, error = %e, "Skipping invalid platform-data secret");
            }
        }
    }

    if platforms.is_empty() {
        bail!(
            "No valid platform-data secrets found in namespace '{namespace}' with selector '{selector}'"
        );
    }

    Ok(platforms)
}

fn platform_entry_from_secret(secret: &Secret) -> anyhow::Result<PlatformListEntry> {
    let data = secret.data.as_ref().context("Secret has no data")?;

    let qe_id = get_secret_string(data, "qe_id").or_else(|_| {
        secret
            .metadata
            .name
            .clone()
            .context("Secret has no name and missing qe_id field")
    })?;

    Ok(PlatformListEntry {
        qe_id,
        pce_id: get_secret_string(data, "pce_id")?,
        cpu_svn: get_secret_string(data, "cpu_svn")?,
        platform_manifest: get_secret_string(data, "platform_manifest")?,
    })
}

fn get_secret_string(
    data: &BTreeMap<String, k8s_openapi::ByteString>,
    key: &str,
) -> anyhow::Result<String> {
    let value = data
        .get(key)
        .with_context(|| format!("Missing '{key}' in platform-data secret"))?;
    String::from_utf8(value.0.clone()).with_context(|| format!("Invalid UTF-8 in '{key}'"))
}

/// Fetch verified PCS data and write directly applicable Kubernetes Secret manifests.
#[instrument(skip(api_key), fields(input_file = %input_file.display(), output_file = %output_file.display(), namespace = namespace))]
pub async fn fetch_secrets_to_file(
    input_file: &Path,
    output_file: &Path,
    namespace: &str,
    api_key: Option<&str>,
) -> anyhow::Result<()> {
    info!(
        path = %input_file.display(),
        "Loading platform list from file"
    );

    let platforms = read_platforms_from_file(input_file)?;

    let http_client = build_pcs_http_client()?;
    let mut secret_manifests = Vec::with_capacity(platforms.len() + 1);
    let mut piid_entries = BTreeMap::new();

    for platform in &platforms {
        info!(qe_id = %platform.qe_id, "Fetching certificates for platform");
        let request_body = PckCertsRequest::from(platform);
        let data_fingerprint = registration_fingerprint(&request_body);
        let platform_cache = fetch_platform_cache(&http_client, api_key, &request_body).await?;
        let pck_secret_name = pck_secret_name(&platform.qe_id);

        piid_entries.insert(platform.qe_id.clone(), platform_cache.piid.clone());
        secret_manifests.push(pck_secret_manifest(&CreatePckSecretInput {
            qe_id: platform.qe_id.clone(),
            fmspc: platform_cache.fmspc,
            cache_data: platform_cache.cache_data,
            piid: platform_cache.piid,
            expiration_time: platform_cache.expiration_time,
            namespace: namespace.to_string(),
            platform_data_fingerprint: data_fingerprint,
            pck_secret_name,
        }));
    }

    secret_manifests.push(piid_index_secret_manifest(namespace, &piid_entries));
    let manifest = serde_json::json!({
        "apiVersion": "v1",
        "kind": "List",
        "items": secret_manifests,
    });
    let yaml = serde_saphyr::to_string(&manifest).context("Failed to serialize Secret YAML")?;
    fs::write(output_file, yaml)
        .with_context(|| format!("Failed to write Secret YAML: {}", output_file.display()))?;

    info!(
        count = platforms.len(),
        output_file = %output_file.display(),
        "Kubernetes Secret YAML written successfully"
    );

    Ok(())
}

fn read_platforms_from_file(input_file: &Path) -> anyhow::Result<Vec<PlatformListEntry>> {
    if !input_file.exists() {
        bail!("Input file does not exist: {}", input_file.display());
    }

    let data = fs::read_to_string(input_file)
        .with_context(|| format!("Failed to read input file: {}", input_file.display()))?;
    let platforms: Vec<PlatformListEntry> =
        serde_json::from_str(&data).context("Failed to parse platform list JSON")?;

    if platforms.is_empty() {
        bail!("Platform list is empty: {}", input_file.display());
    }

    Ok(platforms)
}

/// Export platform list from Kubernetes secrets to a JSON file
pub async fn export_platforms_to_file(
    output_file: PathBuf,
    namespace: String,
    selector: String,
) -> anyhow::Result<()> {
    info!(namespace = %namespace, selector = %selector, "Exporting platform list from Kubernetes");

    let platforms = read_platforms_from_secrets(&namespace, &selector).await?;

    let json = serde_json::to_string_pretty(&platforms)
        .context("Failed to serialize platform list to JSON")?;

    fs::write(&output_file, json)
        .with_context(|| format!("Failed to write export file: {}", output_file.display()))?;

    info!(
        count = platforms.len(),
        path = %output_file.display(),
        "Platform list exported successfully"
    );

    Ok(())
}
