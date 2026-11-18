// Copyright(c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

//! Platform registration with Intel PCS, shared by the Kubernetes watcher and file mode.
//!
//! [`resolve_platform`] does all Intel PCS work for one platform and returns what has to be
//! stored; callers decide whether to apply it to the API server or write it to a file.

use crate::pck_secret::{
    CreatePckSecretInput, pck_secret_manifest, pck_secret_name, piid_index_secret_manifest,
};
use crate::pcs_client::{
    PckCertsRequest, build_pcs_http_client, fetch_pcm, fetch_platform_cache, verify_pcm,
};
use crate::platform_data::{prepare_registration, registration_fingerprint};
use anyhow::{Context, Result, bail};
use k8s_openapi::api::core::v1::Secret;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use tracing::{info, instrument, warn};

/// Verified Intel PCS data for one platform, ready to be stored.
pub struct RegisteredPlatform {
    pub qe_id: String,
    pub pck_secret: CreatePckSecretInput,
    /// Verified Platform Composition Manifest JSON for the PIID index.
    pub pcm: String,
}

/// Fetches and verifies the PCK certificates, TCB info and Platform Composition Manifest for
/// one platform. Nothing is written, so a failure leaves no partial registration behind.
pub async fn resolve_platform(
    http_client: &reqwest::Client,
    api_key: Option<&str>,
    qe_id: &str,
    namespace: &str,
    request_body: &PckCertsRequest,
) -> Result<RegisteredPlatform> {
    info!("Requesting PCK certificates from Intel PCS API");
    let platform_cache = fetch_platform_cache(http_client, api_key, request_body).await?;

    let pcm = fetch_pcm(http_client, api_key, &request_body.platform_manifest).await?;
    verify_pcm(
        &pcm.body,
        &pcm.issuer_chain,
        &platform_cache.pck_issuer_chain,
    )
    .context("Failed to verify the Platform Composition Manifest")?;

    Ok(RegisteredPlatform {
        qe_id: qe_id.to_string(),
        pck_secret: CreatePckSecretInput {
            fmspc: platform_cache.fmspc,
            cache_data: platform_cache.cache_data,
            expiration_time: platform_cache.expiration_time,
            namespace: namespace.to_string(),
            platform_data_fingerprint: registration_fingerprint(request_body),
            pck_secret_name: pck_secret_name(qe_id),
        },
        pcm: pcm.body,
    })
}

/// `kubectl get secret -l type=platform-data -o yaml|json` output.
#[derive(Deserialize)]
struct SecretList {
    items: Vec<Secret>,
}

/// Parses platform-data Secrets and validates them exactly like the watcher does. Invalid
/// Secrets are skipped with a warning.
fn platforms_from_secrets(input: &str) -> Result<Vec<(String, PckCertsRequest)>> {
    let secrets: SecretList = serde_saphyr::from_str(input).context("Failed to parse Secrets")?;

    let platforms: Vec<_> = secrets
        .items
        .into_iter()
        .filter_map(|secret| {
            let name = secret.metadata.name.unwrap_or_default();
            let request = secret
                .data
                .context("Secret has no data")
                .and_then(|data| prepare_registration(&name, &data));
            match request {
                Ok(request) => Some((name, request)),
                Err(e) => {
                    warn!(secret = %name, error = %e, "Skipping invalid platform-data secret");
                    None
                }
            }
        })
        .collect();

    if platforms.is_empty() {
        bail!("No valid platform-data secrets found");
    }
    Ok(platforms)
}

/// Builds a `kubectl apply`-able `List` with the PCK secrets and the PIID index.
fn secret_list_manifest(namespace: &str, platforms: &[RegisteredPlatform]) -> serde_json::Value {
    let piid_entries: BTreeMap<_, _> = platforms
        .iter()
        .map(|p| (p.qe_id.clone(), p.pcm.clone()))
        .collect();
    let items: Vec<_> = platforms
        .iter()
        .map(|p| pck_secret_manifest(&p.pck_secret))
        .chain(std::iter::once(piid_index_secret_manifest(
            namespace,
            &piid_entries,
        )))
        .collect();

    serde_json::json!({
        "apiVersion": "v1",
        "kind": "List",
        "items": items,
    })
}

/// Registers the platform-data Secrets in `input_file` (e.g. the output of
/// `kubectl get secret -l type=platform-data -o yaml`) and writes the resulting Secrets to
/// `output_file`.
#[instrument(skip(api_key), fields(input_file = %input_file.display(), output_file = %output_file.display()))]
pub async fn register_from_file(
    api_key: Option<&str>,
    namespace: &str,
    input_file: &Path,
    output_file: &Path,
) -> Result<()> {
    let input = fs::read_to_string(input_file)
        .with_context(|| format!("Failed to read input file: {}", input_file.display()))?;
    let platforms = platforms_from_secrets(&input)?;

    let http_client = build_pcs_http_client()?;
    let mut registered = Vec::with_capacity(platforms.len());
    for (qe_id, request_body) in &platforms {
        registered.push(
            resolve_platform(&http_client, api_key, qe_id, namespace, request_body)
                .await
                .with_context(|| format!("Failed to register platform {qe_id}"))?,
        );
    }

    let yaml = serde_saphyr::to_string(&secret_list_manifest(namespace, &registered))
        .context("Failed to serialize Secret YAML")?;
    fs::write(output_file, yaml)
        .with_context(|| format!("Failed to write Secret YAML: {}", output_file.display()))?;

    info!(count = registered.len(), "Kubernetes Secret YAML written");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const QE_ID: &str = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4";

    fn platform_secret(name: &str, cpu_svn: &str) -> String {
        let b64 = |s: &str| base64::Engine::encode(&base64::engine::general_purpose::STANDARD, s);
        format!(
            r#"
- apiVersion: v1
  kind: Secret
  metadata:
    name: "{name}"
    labels:
      type: platform-data
  data:
    platform_manifest: {}
    pce_id: {}
    cpu_svn: {}
"#,
            b64("0011aabb"),
            b64("0000"),
            b64(cpu_svn),
        )
    }

    #[test]
    fn platforms_from_kubectl_list_skip_invalid_secrets() {
        let input = format!(
            "apiVersion: v1\nkind: List\nitems:{}{}",
            platform_secret(QE_ID, "0102030405060708090a0b0c0d0e0f10"),
            platform_secret("not-a-qe-id", "0102030405060708090a0b0c0d0e0f10"),
        );

        let platforms = platforms_from_secrets(&input).unwrap();

        assert_eq!(platforms.len(), 1);
        assert_eq!(platforms[0].0, QE_ID);
        assert_eq!(platforms[0].1.cpu_svn, "0102030405060708090a0b0c0d0e0f10");
    }

    #[test]
    fn platforms_from_secrets_rejects_input_without_valid_secrets() {
        let input = format!(
            "apiVersion: v1\nkind: List\nitems:{}",
            platform_secret(QE_ID, "too-short"),
        );

        assert!(platforms_from_secrets(&input).is_err());
    }

    #[test]
    fn secret_list_has_pck_secrets_and_one_piid_index() {
        let platform = |qe_id: &str| RegisteredPlatform {
            qe_id: qe_id.to_string(),
            pck_secret: CreatePckSecretInput {
                fmspc: "AABBCCDDEEFF".to_string(),
                cache_data: vec![1, 2, 3],
                expiration_time: 12345,
                namespace: "ns".to_string(),
                platform_data_fingerprint: "sha256:fp".to_string(),
                pck_secret_name: pck_secret_name(qe_id),
            },
            pcm: format!("pcm-{qe_id}"),
        };

        let list = secret_list_manifest("ns", &[platform("a"), platform("b")]);

        assert_eq!(list["kind"], "List");
        let items = list["items"].as_array().unwrap();
        assert_eq!(items.len(), 3);
        assert_eq!(items[0]["metadata"]["name"], "a-pck");
        assert_eq!(items[1]["metadata"]["name"], "b-pck");
        assert_eq!(items[2]["metadata"]["name"], "piid-index");
        assert_eq!(items[2]["metadata"]["namespace"], "ns");
        assert_eq!(items[2]["data"].as_object().unwrap().len(), 2);
    }
}
