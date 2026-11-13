// Copyright(c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

use crate::FIELD_MANAGER;
use crate::cache::parse_cache_blob;
use anyhow::Context;
use base64::Engine;
use k8s_openapi::api::core::v1::Secret;
use kube::Api;
use kube::api::{Patch, PatchParams};
use std::collections::BTreeMap;
use tracing::{debug, info, instrument, warn};

const ANNOTATION_PLATFORM_DATA_FINGERPRINT: &str =
    "trustedservices.intel.com/platform-data-fingerprint";

const ANNOTATION_EXPIRES_AT: &str = "trustedservices.intel.com/expires-at";

/// Name of the shared secret that maps QE ID → PIID for all registered platforms.
/// Each entry is patched independently using a per-QE-ID SSA field manager so
/// concurrent registrar tasks cannot overwrite each other's keys.
const PIID_INDEX_SECRET_NAME: &str = "piid-index";

pub struct CreatePckSecretInput {
    pub qe_id: String,
    pub fmspc: String,
    pub cache_data: Vec<u8>,
    pub piid: String,
    pub expiration_time: u64,
    pub namespace: String,
    pub platform_data_fingerprint: String,
    pub pck_secret_name: String,
}

/// Generate the name of the PCK secret for a given QE ID with `-pck` suffix.
pub fn pck_secret_name(name: &str) -> String {
    format!("{}-pck", name)
}

pub async fn pck_secret_is_valid(
    secrets: &Api<Secret>,
    pck_secret_name: &str,
    platform_data_fingerprint: &str,
) -> anyhow::Result<bool> {
    let secret = match secrets.get(pck_secret_name).await {
        Ok(secret) => secret,
        Err(kube::Error::Api(err)) if err.code == 404 => return Ok(false),
        Err(err) => {
            return Err(err)
                .with_context(|| format!("Failed to read existing PCK secret {pck_secret_name}"));
        }
    };

    let Some(annotations) = secret.metadata.annotations.as_ref() else {
        warn!(pck_secret = %pck_secret_name, "PCK secret has no annotations, refreshing");
        return Ok(false);
    };

    let Some(recorded_fingerprint) = annotations
        .get(ANNOTATION_PLATFORM_DATA_FINGERPRINT)
        .map(|s| s.as_str())
    else {
        warn!(
            pck_secret = %pck_secret_name,
            annotation = ANNOTATION_PLATFORM_DATA_FINGERPRINT,
            "PCK secret is missing platform-data fingerprint annotation, refreshing"
        );
        return Ok(false);
    };
    if recorded_fingerprint != platform_data_fingerprint {
        debug!(
            pck_secret = %pck_secret_name,
            recorded_fingerprint = %recorded_fingerprint,
            platform_data_fingerprint = %platform_data_fingerprint,
            "PCK secret was created from different platform data, refreshing"
        );
        return Ok(false);
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("System time error while checking PCK secret expiration")?
        .as_secs();
    let Some(expires_at) = annotations.get(ANNOTATION_EXPIRES_AT) else {
        warn!(
            pck_secret = %pck_secret_name,
            annotation = ANNOTATION_EXPIRES_AT,
            "PCK secret is missing expiration annotation, refreshing"
        );
        return Ok(false);
    };
    let expires_at = match expires_at.parse::<u64>() {
        Ok(expires_at) => expires_at,
        Err(err) => {
            warn!(
                pck_secret = %pck_secret_name,
                annotation = ANNOTATION_EXPIRES_AT,
                value = %expires_at,
                error = %err,
                "PCK secret has invalid expiration annotation, refreshing"
            );
            return Ok(false);
        }
    };

    if expires_at <= now {
        debug!(
            pck_secret = %pck_secret_name,
            expires_at,
            now,
            "PCK secret is expired, refreshing"
        );
        return Ok(false);
    }

    let Some(data) = secret.data.as_ref() else {
        warn!(pck_secret = %pck_secret_name, "PCK secret has no data, refreshing");
        return Ok(false);
    };

    let Some(certificate) = data.get("certificate") else {
        warn!(pck_secret = %pck_secret_name, "PCK secret has no certificate field, refreshing");
        return Ok(false);
    };

    if let Err(err) = parse_cache_blob(&certificate.0) {
        warn!(
            pck_secret = %pck_secret_name,
            error = %err,
            "PCK secret certificate field is not a valid QPL cache blob, refreshing"
        );
        return Ok(false);
    }

    Ok(true)
}

pub async fn create_pck_secret(
    secrets: &Api<Secret>,
    input: CreatePckSecretInput,
) -> anyhow::Result<()> {
    let pck_secret = pck_secret_manifest(&input);

    // Create or update the secret using server-side apply. The certificates just fetched from
    // Intel PCS are authoritative, so take over fields that other managers changed instead of
    // failing with a conflict.
    let params = PatchParams::apply(FIELD_MANAGER).force();

    secrets
        .patch(&input.pck_secret_name, &params, &Patch::Apply(&pck_secret))
        .await?;

    // Update the PIID index with this platform's QE ID → PIID mapping.
    // qe_id is derived from the platform-data secret name (which is the qe_id itself).
    patch_piid_index(secrets, &input.namespace, &input.qe_id, &input.piid).await?;

    info!(
        pck_secret = %input.pck_secret_name,
        namespace = %input.namespace,
        fmspc = %input.fmspc,
        "Created/updated secret with PCK certificates"
    );

    Ok(())
}

pub fn pck_secret_manifest(input: &CreatePckSecretInput) -> serde_json::Value {
    let mut labels = BTreeMap::new();
    labels.insert("fmspc".to_string(), input.fmspc.clone());

    serde_json::json!({
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "name": &input.pck_secret_name,
            "namespace": &input.namespace,
            "labels": labels,
            "annotations": {
                ANNOTATION_PLATFORM_DATA_FINGERPRINT: &input.platform_data_fingerprint,
                ANNOTATION_EXPIRES_AT: input.expiration_time.to_string(),
            },
        },
        "type": "Opaque",
        "data": {
            "certificate": base64::engine::general_purpose::STANDARD.encode(&input.cache_data),
        },
    })
}

/// Patch a single `qe_id → piid` entry into the shared PIID index secret.
///
/// Uses a per-`qe_id` SSA field manager so concurrent tasks patching different
/// platforms into the same secret are always safe. The apply is forced so that an
/// entry changed by another manager is taken back; it only covers this platform's key.
#[instrument(skip(secrets))]
async fn patch_piid_index(
    secrets: &Api<Secret>,
    namespace: &str,
    qe_id: &str,
    piid: &str,
) -> anyhow::Result<()> {
    // Per-QE-ID manager so concurrent tasks only own their own piid-index key.
    let field_manager = format!("{FIELD_MANAGER}/{qe_id}");
    let params = PatchParams::apply(&field_manager).force();
    let entries = BTreeMap::from([(qe_id.to_string(), piid.to_string())]);
    let patch = piid_index_secret_manifest(namespace, &entries);

    secrets
        .patch(PIID_INDEX_SECRET_NAME, &params, &Patch::Apply(&patch))
        .await?;

    info!(qe_id = %qe_id, "Updated PIID index");
    Ok(())
}

pub fn piid_index_secret_manifest(
    namespace: &str,
    entries: &BTreeMap<String, String>,
) -> serde_json::Value {
    let data: BTreeMap<_, _> = entries
        .iter()
        .map(|(qe_id, piid)| {
            (
                qe_id,
                base64::engine::general_purpose::STANDARD.encode(piid),
            )
        })
        .collect();

    serde_json::json!({
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "name": PIID_INDEX_SECRET_NAME,
            "namespace": namespace,
        },
        "type": "Opaque",
        "data": data,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> CreatePckSecretInput {
        CreatePckSecretInput {
            qe_id: "00112233445566778899aabbccddeeff".to_string(),
            fmspc: "AABBCCDDEEFF".to_string(),
            cache_data: vec![0, 1, 2, 255],
            piid: "piid-value".to_string(),
            expiration_time: 12345,
            namespace: "intel-dcap-operator-system".to_string(),
            platform_data_fingerprint: "sha256:fingerprint".to_string(),
            pck_secret_name: "00112233445566778899aabbccddeeff-pck".to_string(),
        }
    }

    #[test]
    fn pck_manifest_contains_required_metadata_and_encoded_cache() {
        let input = input();
        let manifest = pck_secret_manifest(&input);

        assert_eq!(manifest["apiVersion"], "v1");
        assert_eq!(manifest["kind"], "Secret");
        assert_eq!(manifest["metadata"]["name"], input.pck_secret_name);
        assert_eq!(manifest["metadata"]["namespace"], input.namespace);
        assert_eq!(manifest["metadata"]["labels"]["fmspc"], input.fmspc);
        assert_eq!(
            manifest["metadata"]["annotations"][ANNOTATION_PLATFORM_DATA_FINGERPRINT],
            input.platform_data_fingerprint
        );
        assert_eq!(
            manifest["metadata"]["annotations"][ANNOTATION_EXPIRES_AT],
            "12345"
        );
        assert_eq!(manifest["type"], "Opaque");
        assert_eq!(manifest["data"]["certificate"], "AAEC/w==");
    }

    #[test]
    fn piid_manifest_uses_qe_id_key_and_encoded_piid() {
        let input = input();
        let entries = BTreeMap::from([(input.qe_id.clone(), input.piid.clone())]);
        let manifest = piid_index_secret_manifest(&input.namespace, &entries);

        assert_eq!(manifest["apiVersion"], "v1");
        assert_eq!(manifest["kind"], "Secret");
        assert_eq!(manifest["metadata"]["name"], PIID_INDEX_SECRET_NAME);
        assert_eq!(manifest["metadata"]["namespace"], input.namespace);
        assert_eq!(manifest["type"], "Opaque");
        assert_eq!(manifest["data"][&input.qe_id], "cGlpZC12YWx1ZQ==");
        assert_eq!(manifest["data"].as_object().map(|data| data.len()), Some(1));
    }

    #[test]
    fn pck_secret_name_uses_id() {
        assert_eq!(
            pck_secret_name("00112233445566778899aabbccddeeff"),
            "00112233445566778899aabbccddeeff-pck"
        );
    }
}
