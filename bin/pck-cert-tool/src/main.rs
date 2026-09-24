// Copyright(c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

mod cache;
mod pcs_client;

use crate::cache::build_cache_blob;
use crate::pcs_client::{PckCertsRequest, fetch_pck_certs, fetch_tcb_info};
use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use clap::{Parser, Subcommand};
use futures::StreamExt;
use k8s_openapi::api::core::v1::Secret;
use kube::{
    Client,
    api::{Api, Patch, PatchParams},
    runtime::{WatchStreamExt, watcher},
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{debug, error, info, instrument, warn};
use x509_parser::der_parser::{oid, oid::Oid, parse_der};
use x509_parser::pem::Pem;
use x509_parser::prelude::{parse_x509_certificate, parse_x509_pem};
use x509_parser::x509::SubjectPublicKeyInfo;

/// Backoff delay between watch error retries to prevent log storms during API server downtime.
const K8S_API_WATCH_ERROR_BACKOFF: Duration = Duration::from_secs(10);

/// EFI variable name for SGX platform manifest
const SGX_PLATFORM_MANIFEST_EFI_VAR: &str =
    "SgxRegistrationServerRequest-304e0796-d515-4698-ac6e-e76cb1a71c28";

/// Expected length, in hex characters, of a QE ID (sgx_key_128bit_t is 16 bytes).
const ID_HEX_LEN: usize = 32;

/// Reserved all-zero QE ID, used as the QPL cache file name when the actual ID isn't
/// guaranteed to be a real QE ID (e.g. a node name in External mode).
const ZERO_ID: &str = "00000000000000000000000000000000";

/// OID for the Intel SGX PCK certificate extension
const SGX_PCK_EXT_OID: Oid<'static> = oid!(1.2.840.113741.1.13.1);

/// OID for the Platform Instance ID (PIID) within the SGX PCK extension — 16-byte octet string
const SGX_PIID_OID: Oid<'static> = oid!(1.2.840.113741.1.13.1.6);

/// TCB Info structure for validation (partial - only fields we need)
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct TcbInfoResponse {
    tcb_info: TcbInfo,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct TcbInfo {
    #[serde(default)]
    tcb_type: u32,
}

/// PCK Certificate entry from Intel PCS API response
#[derive(Deserialize, Serialize, Debug, Clone)]
struct PckCertEntry {
    tcb: serde_json::Value,
    tcbm: String,
    cert: String,
}

/// Platform info fields returned by the external platform-info binary:
/// (cpu_svn, enc_ppid, pce_id, pce_svn, qe_id) — enc_ppid is present in binary output but not used
type PlatformInfo = ([u8; 32], [u8; 4], [u8; 4], [u8; 32]);

#[derive(Parser, Debug)]
#[command(author, version, about = "PCK Certificate Tool", long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Parser, Debug)]
enum Commands {
    /// Get platform data and create Kubernetes secrets
    GetPlatforms(GetPlatformsArgs),
    /// Get PCK certificates from secret and write to file, watching for updates
    GetCertificates(GetCertificatesArgs),
    /// Watch platform-data secrets and register them with Intel PCS to get PCK certificates
    Register(RegisterArgs),
    /// Readiness/liveness probe helpers (exit 0 = ok, 1 = not ok)
    Probe(ProbeArgs),
}

#[derive(Parser, Debug)]
struct GetPlatformsArgs {
    /// Path to the binary that outputs platform info as JSON (cpu_svn, enc_ppid, pce_id, pce_svn, qe_id)
    #[arg(short, long)]
    platform_info_binary: PathBuf,

    /// Optional path to write the derived ID to (e.g. a shared emptyDir volume), so that
    /// other containers (such as pck-certs-watcher) can read it without needing root or SGX
    /// device access to call the platform info binary themselves.
    #[arg(short = 'i', long)]
    id_file: Option<PathBuf>,

    /// Kubernetes namespace (default: default)
    #[arg(short, long, default_value = "default")]
    namespace: String,
}

#[derive(Parser, Debug)]
#[command(group(clap::ArgGroup::new("id_source").required(true).args(["id_file", "id"])))]
struct GetCertificatesArgs {
    /// Path to a file containing the real SGX QE ID (e.g. written by `get-platforms
    /// --id-file` onto a shared volume). Mutually exclusive with --id. Avoids needing SGX
    /// enclave/device access in this container. The value MUST be the real SGX QE ID for this
    /// node: it's used to build both the `<id>-pck` secret name and the on-disk cache file
    /// name, and the SGX DCAP Quote Provider Library looks up that cache file by the node's
    /// actual QE ID at runtime.
    #[arg(short = 'i', long)]
    id_file: Option<PathBuf>,

    /// Literal ID value to use directly, without reading a file (e.g. `$(NODE_NAME)` in
    /// External mode, where there is no `platform-registration` container to derive a real QE
    /// ID). Mutually exclusive with --id-file. Used as-is to build the `<id>-pck` secret name,
    /// but since it is not guaranteed to be a real QE ID, the on-disk cache file is always
    /// written under the reserved all-zero ID instead (see `ZERO_ID`).
    #[arg(long)]
    id: Option<String>,

    /// Output directory path
    #[arg(short, long)]
    output_dir: PathBuf,

    /// Kubernetes namespace (default: default)
    #[arg(short, long, default_value = "default")]
    namespace: String,
}

#[derive(Parser, Debug)]
struct RegisterArgs {
    /// Intel PCS API key for Ocp-Apim-Subscription-Key header (optional)
    #[arg(short, long)]
    api_key: Option<String>,

    /// Kubernetes namespace (default: default)
    #[arg(short, long, default_value = "default")]
    namespace: String,
}

#[derive(Parser, Debug)]
struct ProbeArgs {
    #[command(subcommand)]
    command: ProbeCommands,
}

#[derive(Subcommand, Debug)]
enum ProbeCommands {
    /// Check whether a directory is non-empty; used as a readiness probe to gate tdx-qgs startup
    CacheReady(ProbePathArgs),
    /// Connect to a Unix socket; used as a liveness probe for tdx-qgs
    CheckSocket(ProbePathArgs),
}

#[derive(Parser, Debug)]
struct ProbePathArgs {
    /// Path to check
    path: PathBuf,
}

fn copy_fixed_hex_field<const N: usize>(value: &str, field: &str) -> Result<[u8; N]> {
    let bytes = value.as_bytes();
    if bytes.len() != N {
        bail!(
            "{field} has invalid length: got {} bytes, expected {N}",
            bytes.len()
        );
    }
    if !bytes.iter().all(u8::is_ascii_hexdigit) {
        bail!("{field} has invalid content: expected a {N}-character hex string, got {value:?}");
    }

    let mut out = [0u8; N];
    out.copy_from_slice(bytes);
    Ok(out)
}

fn get_platform_info(binary_path: &Path) -> Result<PlatformInfo> {
    debug!(
        path = %binary_path.display(),
        "Calling external binary to get platform info"
    );

    let output = Command::new(binary_path)
        .output()
        .context("Failed to execute platform info binary")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("Platform info binary failed: {stderr}");
    }

    let json_output = String::from_utf8_lossy(&output.stdout).trim().to_string();

    if json_output.is_empty() {
        bail!("Platform info binary returned empty output");
    }

    // Parse JSON and extract all fields
    let json: serde_json::Value =
        serde_json::from_str(&json_output).context("Failed to parse platform info JSON output")?;

    let cpu_svn_str = json
        .get("cpu_svn")
        .and_then(|v| v.as_str())
        .context("Missing or invalid cpu_svn field in JSON output")?;

    let pce_id_str = json
        .get("pce_id")
        .and_then(|v| v.as_str())
        .context("Missing or invalid pce_id field in JSON output")?;

    let pce_svn_str = json
        .get("pce_svn")
        .and_then(|v| v.as_str())
        .context("Missing or invalid pce_svn field in JSON output")?;

    let qe_id_str = json
        .get("qe_id")
        .and_then(|v| v.as_str())
        .context("Missing or invalid qe_id field in JSON output")?;

    let cpu_svn = copy_fixed_hex_field::<32>(cpu_svn_str, "cpu_svn")?;
    let pce_id = copy_fixed_hex_field::<4>(pce_id_str, "pce_id")?;
    let pce_svn = copy_fixed_hex_field::<4>(pce_svn_str, "pce_svn")?;
    let qe_id = copy_fixed_hex_field::<32>(qe_id_str, "qe_id")?;

    debug!(qe_id = %qe_id_str, "Retrieved platform info");
    Ok((cpu_svn, pce_id, pce_svn, qe_id))
}

/// Read the ID previously written to a plain-text file by `get-platforms --id-file`,
/// validating it's a well-formed QE ID (fixed-length hex string).
fn get_id_from_file(path: &Path) -> Result<String> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("Failed to read ID file: {}", path.display()))?;
    let id = contents.trim().to_string();
    if id.len() != ID_HEX_LEN || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!(
            "ID file {} has invalid content: expected a {ID_HEX_LEN}-character hex string, \
             got {:?}",
            path.display(),
            id
        );
    }
    Ok(id)
}

/// Write the ID to a plain-text file so sibling containers (e.g. pck-certs-watcher)
/// sharing a volume can read it without needing SGX enclave/device access themselves.
fn write_id_file(path: &Path, id: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create directory: {}", parent.display()))?;
    }
    fs::write(path, id).with_context(|| format!("Failed to write ID file: {}", path.display()))?;
    debug!(path = %path.display(), "Wrote ID file");
    Ok(())
}

/// Verify a PCK certificate against the SGX Intermediate CA's public key
fn verify_certificate(cert_pem: &str, issuer_spki: &SubjectPublicKeyInfo<'_>) -> Result<bool> {
    let (_, pem) = parse_x509_pem(cert_pem.as_bytes())
        .map_err(|e| anyhow!("Failed to parse PCK certificate PEM: {e}"))?;
    let (_, cert) = parse_x509_certificate(&pem.contents)
        .map_err(|e| anyhow!("Failed to parse PCK certificate: {e}"))?;
    Ok(cert.verify_signature(Some(issuer_spki)).is_ok())
}

fn extract_piid(pem: &str) -> Result<String> {
    let (_, pem_obj) =
        parse_x509_pem(pem.as_bytes()).map_err(|e| anyhow!("Failed to parse PEM: {e}"))?;
    let (_, cert) = parse_x509_certificate(&pem_obj.contents)
        .map_err(|e| anyhow!("Failed to parse certificate: {e}"))?;

    let ext = cert
        .get_extension_unique(&SGX_PCK_EXT_OID)
        .context("Duplicate SGX PCK extension in certificate")?
        .context("SGX PCK extension not found in certificate")?;

    let (_, outer) =
        parse_der(ext.value).map_err(|e| anyhow!("Failed to parse SGX extension DER: {e}"))?;

    for item in outer
        .as_sequence()
        .context("SGX extension is not a SEQUENCE")?
    {
        let inner = item
            .as_sequence()
            .context("SGX sub-extension is not a SEQUENCE")?;

        if inner.len() < 2 {
            continue;
        }

        let item_oid = inner[0].as_oid_val().context("Failed to parse sub-OID")?;

        if item_oid == SGX_PIID_OID {
            let bytes = inner[1]
                .as_slice()
                .context("PIID value is not an OCTET STRING")?;

            if bytes.len() != 16 {
                bail!("Expected 16 bytes for PIID, got {}", bytes.len());
            }

            return Ok(bytes.iter().map(|b| format!("{b:02x}")).collect());
        }
    }

    bail!("PIID OID (1.2.840.113741.1.13.1.6) not found in SGX PCK extension")
}

/// Filter and verify PCK certificates
#[instrument(skip(pck_certs_json, cert_chain))]
fn filter_and_verify_pck_certs(pck_certs_json: &str, cert_chain: &str) -> Result<(String, String)> {
    // Parse the JSON array
    let pck_certs: Vec<PckCertEntry> =
        serde_json::from_str(pck_certs_json).context("Failed to parse PCK certificates JSON")?;

    debug!(total = pck_certs.len(), "Total PCK certificates received");

    // Decode the URL-encoded certificate chain
    let decoded_chain =
        urlencoding::decode(cert_chain).context("Failed to decode certificate chain")?;

    // Parse the certificate chain once (optimization - avoid parsing for each cert)
    let chain_der: Vec<Vec<u8>> = Pem::iter_from_buffer(decoded_chain.as_bytes())
        .map(|r| {
            r.map(|pem| pem.contents)
                .context("Failed to parse PEM block in chain")
        })
        .collect::<Result<_>>()?;

    // Validate chain structure: Must contain exactly 2 certificates
    if chain_der.len() != 2 {
        bail!(
            "Invalid certificate chain: expected 2 certificates (Root CA + Intermediate CA), got {}",
            chain_der.len()
        );
    }

    // Determine which certificate is root and which is intermediate
    // Root CA is self-signed (verifies against its own key)
    debug!("Validating certificate chain");
    let (_, cert0) = parse_x509_certificate(&chain_der[0])
        .map_err(|e| anyhow!("Failed to parse certificate [0]: {e}"))?;
    let (_, cert1) = parse_x509_certificate(&chain_der[1])
        .map_err(|e| anyhow!("Failed to parse certificate [1]: {e}"))?;

    let cert0_self_signed = cert0.verify_signature(None).is_ok();
    let cert1_self_signed = cert1.verify_signature(None).is_ok();

    let (root_cert, intermediate_cert) = if cert0_self_signed && !cert1_self_signed {
        debug!("Certificate chain order: [0]=Root CA, [1]=Intermediate CA");
        (cert0, cert1)
    } else if cert1_self_signed && !cert0_self_signed {
        debug!("Certificate chain order: [1]=Root CA, [0]=Intermediate CA");
        (cert1, cert0)
    } else {
        bail!("Certificate chain validation failed: cannot identify self-signed root certificate");
    };

    // Verify that Intermediate CA is signed by Root CA
    intermediate_cert
        .verify_signature(Some(&root_cert.tbs_certificate.subject_pki))
        .context("Certificate chain validation failed: Intermediate CA is not signed by Root CA")?;
    debug!("Certificate chain validated (Root CA self-signed -> Intermediate CA)");

    let intermediate_spki = &intermediate_cert.tbs_certificate.subject_pki;

    // Filter out "Not available" certificates and verify remaining ones
    let mut filtered_certs = Vec::new();
    let mut skipped_unavailable = 0;

    for (idx, entry) in pck_certs.into_iter().enumerate() {
        if entry.cert == "Not available" {
            skipped_unavailable += 1;
            continue;
        }

        // URL-decode the certificate for verification, but keep original format for storage
        let decoded_cert = urlencoding::decode(&entry.cert)
            .context(format!("Failed to URL-decode certificate at index {idx}"))?;

        // Verify the PCK certificate against the Intermediate CA
        // Fail immediately if verification fails
        match verify_certificate(&decoded_cert, intermediate_spki) {
            Ok(true) => {
                // Store the entry with the original URL-encoded certificate
                filtered_certs.push(entry);
            }
            Ok(false) => {
                bail!("Certificate at index {idx} failed signature verification");
            }
            Err(e) => {
                let preview = if entry.cert.len() > 100 {
                    format!("{}...", &entry.cert[..100])
                } else {
                    entry.cert.clone()
                };
                bail!(
                    "Certificate at index {idx} verification error: {e}\nCert preview: {preview}"
                );
            }
        }
    }

    if filtered_certs.is_empty() {
        bail!("No valid PCK certificates found after filtering");
    }

    info!(
        valid = filtered_certs.len(),
        unavailable = skipped_unavailable,
        "Filtered PCK certificates"
    );

    // Serialize back to JSON
    let filtered_json = serde_json::to_string(&filtered_certs)
        .context("Failed to serialize filtered certificates")?;

    // Extract PIID from the topmost (first) certificate in the filtered list
    let first_cert_pem = urlencoding::decode(&filtered_certs[0].cert)
        .context("Failed to URL-decode first PCK certificate")?;
    let piid = extract_piid(&first_cert_pem)
        .context("Failed to extract PIID from first PCK certificate")?;

    Ok((filtered_json, piid))
}

fn get_platform_manifest() -> Result<Option<String>> {
    debug!("Reading platform manifest from EFI variable");

    // EFI variables are files under /sys/firmware/efi/efivars/{name}-{guid}.
    // file layout: EFI attrs(4) | Intel version(2) | Intel size(2) | structure data
    let path = format!("/sys/firmware/efi/efivars/{SGX_PLATFORM_MANIFEST_EFI_VAR}");
    let mut file = match std::fs::File::open(&path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            warn!(
                "EFI variable not found (non-EFI system or variable not set), skipping platform manifest"
            );
            return Ok(None);
        }
        Err(e) => return Err(anyhow!("Failed to open EFI variable {path}: {e}")),
    };

    let mut header = [0u8; 8];
    file.read_exact(&mut header)
        .context("EFI variable file too short to contain header")?;

    let declared_size = u16::from_le_bytes([header[6], header[7]]) as usize;

    let mut structure_data = Vec::new();
    file.read_to_end(&mut structure_data)
        .context("Failed to read EFI variable structure data")?;

    if structure_data.len() != declared_size {
        bail!(
            "Platform manifest size mismatch: header declares {} bytes, file has {}",
            declared_size,
            structure_data.len()
        );
    }

    let manifest = structure_data
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();

    debug!(bytes = structure_data.len(), "Retrieved platform manifest");

    Ok(Some(manifest))
}

#[instrument(name = "get-platforms", skip(platform_info_binary, id_file), fields(namespace = %namespace, secret = tracing::field::Empty))]
async fn create_secret(
    platform_info_binary: &Path,
    id_file: Option<&Path>,
    namespace: &str,
) -> Result<()> {
    // Get platform info from external binary (fixed-size arrays, stack allocated)
    let (cpu_svn, pce_id, pce_svn, qe_id) = get_platform_info(platform_info_binary)?;

    // Convert qe_id to string for secret name
    let qe_id_str = std::str::from_utf8(&qe_id).context("Invalid UTF-8 in qe_id")?;
    tracing::Span::current().record("secret", qe_id_str);

    // Share the ID with sibling containers (e.g. pck-certs-watcher) via a shared volume,
    // so they don't need SGX enclave/device access just to learn it.
    if let Some(path) = id_file {
        write_id_file(path, qe_id_str)?;
    }

    let pce_id_str = std::str::from_utf8(&pce_id).context("Invalid UTF-8 in pce_id")?;
    let cpu_svn_str = std::str::from_utf8(&cpu_svn).context("Invalid UTF-8 in cpu_svn")?;
    let pce_svn_str = std::str::from_utf8(&pce_svn).context("Invalid UTF-8 in pce_svn")?;
    info!("Creating secret");

    // Read platform manifest from EFI variable; may be absent after first registration
    let platform_manifest = get_platform_manifest()?;
    if platform_manifest.is_none() {
        info!(
            "Platform manifest EFI variable not available; omitting from patch (existing value preserved by SSA)"
        );
    }

    debug!("Prepared secret data");

    // Create Kubernetes client
    let client = Client::try_default().await?;

    let secrets: Api<Secret> = Api::namespaced(client, namespace);

    // Build secret; omit platform_manifest when unavailable so SSA leaves the
    // previously stored value intact (cpu_svn/pce_id updates after initial registration).
    let mut secret = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "name": qe_id_str,
            "namespace": namespace,
            "labels": {
                "type": "platform-data"
            }
        },
        "type": "Opaque",
        "stringData": {
            "enc_ppid": "",
            "pce_id": pce_id_str,
            "cpu_svn": cpu_svn_str,
            "pce_svn": pce_svn_str,
            "qe_id": qe_id_str,
        },
    });
    if let Some(ref manifest) = platform_manifest {
        secret["stringData"]["platform_manifest"] = serde_json::json!(manifest);
    }

    // Create or update the secret using server-side apply
    let params = PatchParams::apply("pck-cert-tool");

    secrets
        .patch(qe_id_str, &params, &Patch::Apply(&secret))
        .await?;

    info!("Successfully created/updated secret");
    Ok(())
}

#[instrument(skip(cert_data), fields(cache_id = %cache_id))]
fn write_certificate_to_file(cache_id: &str, output_dir: &Path, cert_data: &[u8]) -> Result<()> {
    // Create filename: <cache_id>_0000
    let filename = format!("{cache_id}_0000");
    let file_path = output_dir.join(&filename);

    debug!(path = %file_path.display(), "Writing certificate to file");

    // Write the certificate data to file
    let mut file = fs::File::create(&file_path)?;
    file.write_all(cert_data)?;
    file.flush()?;

    info!(path = %file_path.display(), "Certificate written successfully");
    Ok(())
}

fn write_certificate_from_secret(
    cache_id: &str,
    output_dir: &Path,
    secret: &Secret,
    event: &str,
) -> Result<()> {
    let Some(data) = secret.data.as_ref() else {
        warn!(event = %event, "Secret has no data");
        return Ok(());
    };

    let Some(cert_data) = data.get("certificate") else {
        warn!(event = %event, "Secret has no 'certificate' field");
        return Ok(());
    };

    write_certificate_to_file(cache_id, output_dir, cert_data.0.as_slice())
}

/// Resolves the `(id, cache_id)` pair for `get-certificates` from its two mutually exclusive ID
/// sources. `id` names the `<id>-pck` secret to watch. `cache_id` names the on-disk QPL cache
/// file. When the ID comes from a file (the default Online/Offline modes), it's guaranteed to be
/// the node's real SGX QE ID, so both are the same value. When it's passed literally (e.g.
/// `$(NODE_NAME)` in External mode), it isn't guaranteed to be a real QE ID, so the cache file
/// always uses the reserved all-zero ID instead — an arbitrary/unrelated cache file name would
/// never be found by the SGX DCAP Quote Provider Library at runtime anyway.
fn resolve_id(id_file: Option<&Path>, literal_id: Option<&str>) -> Result<(String, String)> {
    if let Some(path) = id_file {
        let id = get_id_from_file(path)?;
        let cache_id = id.clone();
        Ok((id, cache_id))
    } else {
        let id = literal_id
            .context("one of --id-file or --id is required")?
            .trim()
            .to_string();
        if id.is_empty() {
            bail!("--id must not be empty");
        }
        Ok((id, ZERO_ID.to_string()))
    }
}

#[instrument(name = "get-certificates", skip(output_dir), fields(namespace = %namespace, secret = tracing::field::Empty, output_dir = %output_dir.display()))]
async fn watch_certificates(
    id: &str,
    cache_id: &str,
    output_dir: &Path,
    namespace: &str,
) -> Result<()> {
    // Secret name is <id>-pck
    let secret_name = format!("{id}-pck");
    tracing::Span::current().record("secret", &secret_name);

    info!("Starting certificate watcher");

    // Ensure output directory exists
    if !output_dir.exists() {
        fs::create_dir_all(output_dir)?;
        debug!("Created output directory");
    }

    // Create Kubernetes client
    let client = Client::try_default().await?;
    let secrets: Api<Secret> = Api::namespaced(client, namespace);
    let mut last_seen_resource_version: Option<String> = None;

    // Try to read the secret initially
    match secrets.get(&secret_name).await {
        Ok(secret) => {
            info!("Found existing secret");
            write_certificate_from_secret(cache_id, output_dir, &secret, "initial-read")?;
            last_seen_resource_version = secret.metadata.resource_version.clone();
        }
        Err(e) => {
            warn!(error = %e, "Secret not found yet, waiting for creation");
        }
    }

    // Set up watch for the specific secret
    let watch_config = watcher::Config::default()
        .fields(&format!("metadata.name={secret_name}"))
        .timeout(200);

    let mut watch_stream = watcher(secrets, watch_config).applied_objects().boxed();

    info!("Watching for updates");

    // Set up signal handler for graceful shutdown
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;

    // Watch for changes until SIGTERM
    loop {
        tokio::select! {
            result = watch_stream.next() => {
                match result {
                    Some(Ok(secret)) => {
                        let resource_version = secret.metadata.resource_version.clone();
                        if resource_version.is_some()
                            && resource_version == last_seen_resource_version
                        {
                            debug!(
                                resource_version = ?resource_version,
                                "Skipping already processed secret version"
                            );
                            continue;
                        }

                        info!("Secret updated");
                        write_certificate_from_secret(cache_id, output_dir, &secret, "watch-update")?;
                        last_seen_resource_version = resource_version;
                    }
                    Some(Err(e)) => {
                        error!(error = %e, "Watch error");
                        sleep(K8S_API_WATCH_ERROR_BACKOFF).await;
                    }
                    None => {
                        info!("Watch stream ended");
                        break;
                    }
                }
            }
            _ = sigterm.recv() => {
                info!("Received SIGTERM, shutting down gracefully");
                break;
            }
        }
    }

    Ok(())
}

/// Name of the shared secret that maps QE ID → PIID for all registered platforms.
/// Each entry is patched independently using a per-QE-ID SSA field manager so
/// concurrent registrar tasks cannot overwrite each other's keys.
const PIID_INDEX_SECRET_NAME: &str = "piid-index";

/// Patch a single `qe_id → piid` entry into the shared PIID index secret.
///
/// Uses a per-`qe_id` SSA field manager so concurrent tasks patching different
/// platforms into the same secret are always safe.
#[instrument(skip(secrets))]
async fn patch_piid_index(secrets: &Api<Secret>, qe_id: &str, piid: &str) -> Result<()> {
    let field_manager = format!("pck-cert-tool/{qe_id}");
    let params = PatchParams::apply(&field_manager);

    let patch = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "name": PIID_INDEX_SECRET_NAME,
        },
        "type": "Opaque",
        "data": {
            qe_id: base64::engine::general_purpose::STANDARD.encode(piid),
        },
    });

    secrets
        .patch(PIID_INDEX_SECRET_NAME, &params, &Patch::Apply(&patch))
        .await?;

    info!(qe_id = %qe_id, "Updated PIID index");
    Ok(())
}

#[instrument(name = "register", skip(api_key), fields(namespace = %namespace))]
async fn register_platforms(api_key: Option<&str>, namespace: &str) -> Result<()> {
    // Create Kubernetes client
    let client = Client::try_default().await?;
    let secrets: Api<Secret> = Api::namespaced(client.clone(), namespace);

    // Create HTTP client for Intel PCS API with retry on 5xx / 429
    let retry_policy = reqwest::retry::for_host("api.trustedservices.intel.com")
        .max_retries_per_request(3)
        .classify_fn(|req_rep| {
            let retryable = req_rep.error().is_some()
                || req_rep
                    .status()
                    .map(|s| s.is_server_error() || s == reqwest::StatusCode::TOO_MANY_REQUESTS)
                    .unwrap_or(false);
            if retryable {
                req_rep.retryable()
            } else {
                req_rep.success()
            }
        });
    let http_client = reqwest::Client::builder()
        .retry(retry_policy)
        .build()
        .context("Failed to build HTTP client")?;

    // Set up watch with label selector for platform-data secrets
    let watch_config = watcher::Config::default().labels("type=platform-data");
    let mut watch_stream = watcher(secrets.clone(), watch_config)
        .applied_objects()
        .boxed();

    info!("Watching for platform-data secrets");

    // Track spawned tasks for graceful shutdown
    let mut tasks: Vec<tokio::task::JoinHandle<()>> = Vec::new();

    // Set up signal handler for graceful shutdown
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;

    // Watch for changes until SIGTERM
    loop {
        // Prune finished tasks to prevent unbounded growth of the task list
        tasks.retain(|handle: &tokio::task::JoinHandle<()>| !handle.is_finished());

        tokio::select! {
            result = watch_stream.next() => {
                match result {
                    Some(Ok(secret)) => {
                        let secret_name = secret
                            .metadata
                            .name
                            .as_ref()
                            .context("Secret has no name")?
                            .clone();

                        info!(platform_secret = %secret_name, "Detected platform-data secret");

                        // Spawn a task to handle this secret asynchronously
                        let secrets_clone = secrets.clone();
                        let http_client_clone = http_client.clone();
                        let api_key_clone = api_key.map(|s| s.to_string());

                        let handle = tokio::spawn(async move {
                            if let Err(e) = process_platform_secret(
                                &secrets_clone,
                                &http_client_clone,
                                api_key_clone.as_deref(),
                                secret,
                            )
                            .await
                            {
                                error!(platform_secret = %secret_name, error = ?e, "Error processing platform-data secret");
                            }
                        });

                        tasks.push(handle);
                    }
                    Some(Err(e)) => {
                        warn!(error = %e, "Watch error");
                        sleep(K8S_API_WATCH_ERROR_BACKOFF).await;
                    }
                    None => {
                        info!("Watch stream ended");
                        break;
                    }
                }
            }
            _ = sigterm.recv() => {
                info!("Received SIGTERM, shutting down gracefully");
                break;
            }
        }
    }

    // Wait for all in-flight tasks to complete
    if !tasks.is_empty() {
        info!(
            count = tasks.len(),
            "Waiting for in-flight tasks to complete"
        );
        for handle in tasks {
            if let Err(err) = handle.await {
                error!(error = %err, "Platform secret task failed to join");
            }
        }
        info!("All tasks completed");
    }

    Ok(())
}

const ANNOTATION_PLATFORM_DATA_RV: &str =
    "trustedservices.intel.com/platform-data-resource-version";
const ANNOTATION_EXPIRES_AT: &str = "trustedservices.intel.com/expires-at";

async fn pck_secret_is_valid(
    secrets: &Api<Secret>,
    pck_secret_name: &str,
    platform_data_resource_version: &str,
) -> Result<bool> {
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

    let Some(recorded_rv) = annotations
        .get(ANNOTATION_PLATFORM_DATA_RV)
        .map(|s| s.as_str())
    else {
        warn!(
            pck_secret = %pck_secret_name,
            annotation = ANNOTATION_PLATFORM_DATA_RV,
            "PCK secret is missing platform-data resource version annotation, refreshing"
        );
        return Ok(false);
    };
    if recorded_rv != platform_data_resource_version {
        debug!(
            pck_secret = %pck_secret_name,
            recorded_rv = %recorded_rv,
            platform_data_resource_version = %platform_data_resource_version,
            "PCK secret was created from a different platform-data version, refreshing"
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

    if certificate.0.is_empty() {
        warn!(pck_secret = %pck_secret_name, "PCK secret certificate field is empty, refreshing");
        return Ok(false);
    }

    Ok(true)
}

#[instrument(skip(secrets, http_client, api_key, secret), fields(platform_secret = tracing::field::Empty))]
async fn process_platform_secret(
    secrets: &Api<Secret>,
    http_client: &reqwest::Client,
    api_key: Option<&str>,
    secret: Secret,
) -> Result<()> {
    // Extract secret name and namespace from metadata
    let secret_name = secret
        .metadata
        .name
        .as_ref()
        .context("Secret has no name")?;

    let namespace = secret
        .metadata
        .namespace
        .as_ref()
        .context("Secret has no namespace")?;

    tracing::Span::current().record("platform_secret", secret_name);

    let pck_secret_name = format!("{secret_name}-pck");

    let platform_data_resource_version = secret
        .metadata
        .resource_version
        .as_deref()
        .context("Secret has no resource_version")?;

    if pck_secret_is_valid(secrets, &pck_secret_name, platform_data_resource_version).await? {
        info!(pck_secret = %pck_secret_name, "PCK secret is valid and platform data unchanged, skipping PCS call");
        return Ok(());
    }

    // Extract platform_manifest and pce_id from the secret
    // The k8s-openapi library automatically base64-decodes .data fields
    // ByteString.0 contains the raw bytes which we interpret as UTF-8 hex strings
    let data = secret.data.as_ref().context("Secret has no data")?;

    // Parse request body from secret data
    let request_body = PckCertsRequest::from_secret_data(data)?;

    info!("Requesting PCK certificates from Intel PCS API");

    // Fetch PCK certificates from Intel PCS API
    let pck_response = fetch_pck_certs(http_client, api_key, &request_body).await?;
    let fmspc = pck_response.fmspc;
    let cert_chain = pck_response.cert_chain;
    let pck_certs_json = pck_response.pck_certs_json;

    // Filter and verify PCK certificates
    debug!("Filtering and verifying PCK certificates");
    let (filtered_pck_certs_json, piid) =
        filter_and_verify_pck_certs(&pck_certs_json, &cert_chain)?;

    let tcb_info_response = fetch_tcb_info(http_client, &fmspc).await?;
    let tcb_info = tcb_info_response.body;

    // Validate TCB Info structure
    debug!("Validating TCB Info");
    let tcb_info_parsed: TcbInfoResponse =
        serde_json::from_str(&tcb_info).context("Failed to parse TCB Info JSON response")?;

    if tcb_info_parsed.tcb_info.tcb_type != 0 {
        bail!(
            "Invalid TCB Info: tcbType must be 0 (Standard SGX), got {}. \
             This tool only supports standard SGX TCB Info (tcbType=0).",
            tcb_info_parsed.tcb_info.tcb_type
        );
    }
    debug!("TCB Info validation passed (tcbType=0)");

    let (cache_data, expiration_time) = build_cache_blob(
        &request_body.cpu_svn,
        &tcb_info,
        &cert_chain,
        &filtered_pck_certs_json,
    )?;

    // Create new secret with -pck suffix
    let mut labels = BTreeMap::new();
    labels.insert("fmspc".to_string(), fmspc.clone());

    let pck_secret = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "name": pck_secret_name,
            "namespace": namespace,
            "labels": labels,
            "annotations": {
                ANNOTATION_PLATFORM_DATA_RV: platform_data_resource_version,
                ANNOTATION_EXPIRES_AT: expiration_time.to_string(),
            },
        },
        "type": "Opaque",
        "data": {
            "certificate": base64::engine::general_purpose::STANDARD.encode(&cache_data),
        },
    });

    // Create or update the secret using server-side apply
    let params = PatchParams::apply("pck-cert-tool");

    secrets
        .patch(&pck_secret_name, &params, &Patch::Apply(&pck_secret))
        .await?;

    // Update the PIID index with this platform's QE ID → PIID mapping.
    // qe_id is derived from the platform-data secret name (which is the qe_id itself).
    patch_piid_index(secrets, secret_name, &piid).await?;

    info!(
        pck_secret = %pck_secret_name,
        namespace = %namespace,
        fmspc = %fmspc,
        "Created/updated secret with PCK certificates"
    );

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing subscriber with INFO level by default
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();

    match args.command {
        Commands::GetPlatforms(get_args) => {
            if !get_args.platform_info_binary.exists() {
                bail!(
                    "Platform info binary does not exist: {}",
                    get_args.platform_info_binary.display()
                );
            }

            create_secret(
                &get_args.platform_info_binary,
                get_args.id_file.as_deref(),
                &get_args.namespace,
            )
            .await?;
        }
        Commands::GetCertificates(get_args) => {
            let (id, cache_id) = resolve_id(get_args.id_file.as_deref(), get_args.id.as_deref())?;
            watch_certificates(&id, &cache_id, &get_args.output_dir, &get_args.namespace).await?;
        }
        Commands::Register(reg_args) => {
            let api_key = reg_args.api_key.or_else(|| {
                std::env::var("INTEL_PCS_API_KEY")
                    .ok()
                    .filter(|s| !s.is_empty())
            });
            register_platforms(api_key.as_deref(), &reg_args.namespace).await?;
        }
        Commands::Probe(probe_args) => match probe_args.command {
            ProbeCommands::CacheReady(args) => {
                let populated = fs::read_dir(&args.path)
                    .ok()
                    .and_then(|mut entries| entries.next())
                    .is_some();
                if !populated {
                    eprintln!(
                        "cache-ready: {} is empty or does not exist",
                        args.path.display()
                    );
                    std::process::exit(1);
                }
            }
            ProbeCommands::CheckSocket(args) => {
                if let Err(e) = std::os::unix::net::UnixStream::connect(&args.path) {
                    eprintln!(
                        "check-socket: cannot connect to {}: {e}",
                        args.path.display()
                    );
                    std::process::exit(1);
                }
            }
        },
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A well-formed, 32-hex-character sample ID for tests.
    const SAMPLE_ID: &str = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4";

    /// Creates a fresh temp directory for a test case, tagged for easy identification.
    fn unique_temp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "pck-cert-tool-test-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_id_file_roundtrip() {
        let dir = unique_temp_dir("roundtrip");
        let file = dir.join("id");

        write_id_file(&file, SAMPLE_ID).expect("write should succeed");
        let read_back = get_id_from_file(&file).expect("read should succeed");
        assert_eq!(read_back, SAMPLE_ID);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_id_file_trims_whitespace() {
        let dir = unique_temp_dir("trim");
        let file = dir.join("id");
        std::fs::write(&file, format!("  {SAMPLE_ID}\n")).unwrap();

        let read_back = get_id_from_file(&file).expect("read should succeed");
        assert_eq!(read_back, SAMPLE_ID);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_id_file_invalid_content_errors() {
        let dir = unique_temp_dir("invalid");
        let cases = [
            ("empty", "   \n"),
            // Too short to be a valid 32-hex-character ID.
            ("wrong_length", "a1b2c3d4e5f6"),
            // Correct length, but contains a non-hex character.
            ("non_hex", "g1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"),
        ];
        for (case, content) in cases {
            let file = dir.join(case);
            std::fs::write(&file, content).unwrap();
            assert!(
                get_id_from_file(&file).is_err(),
                "case {case:?} should have errored"
            );
        }

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_copy_fixed_hex_field_accepts_valid_hex() {
        let out = copy_fixed_hex_field::<8>("deadbeef", "test_field").expect("should succeed");
        assert_eq!(out, *b"deadbeef");
    }

    #[test]
    fn test_copy_fixed_hex_field_rejects_wrong_length() {
        assert!(copy_fixed_hex_field::<8>("dead", "test_field").is_err());
        assert!(copy_fixed_hex_field::<8>("deadbeefcafe", "test_field").is_err());
    }

    #[test]
    fn test_copy_fixed_hex_field_rejects_non_hex_content() {
        // Correct length, but contains non-hex characters.
        assert!(copy_fixed_hex_field::<8>("deadbeeg", "test_field").is_err());
        assert!(copy_fixed_hex_field::<8>("../../etc", "test_field").is_err());
    }

    #[test]
    fn test_id_file_missing_errors() {
        let path = std::env::temp_dir().join("pck-cert-tool-test-nonexistent-id-file");
        assert!(get_id_from_file(&path).is_err());
    }

    #[test]
    fn test_resolve_id_from_file_uses_id_as_cache_id() {
        let dir = unique_temp_dir("resolve-from-file");
        let file = dir.join("id");
        write_id_file(&file, SAMPLE_ID).unwrap();

        let (id, cache_id) = resolve_id(Some(&file), None).expect("should resolve");
        assert_eq!(id, SAMPLE_ID);
        assert_eq!(cache_id, SAMPLE_ID);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_resolve_id_from_literal_uses_zero_id_as_cache_id() {
        let (id, cache_id) = resolve_id(None, Some("some-node-name")).expect("should resolve");
        assert_eq!(id, "some-node-name");
        assert_eq!(cache_id, ZERO_ID);
    }

    #[test]
    fn test_resolve_id_empty_literal_errors() {
        assert!(resolve_id(None, Some("   ")).is_err());
    }

    #[test]
    fn test_resolve_id_neither_source_errors() {
        assert!(resolve_id(None, None).is_err());
    }

    #[test]
    fn test_tcb_info_validation_success() {
        // Test valid TCB info with tcbType = 0
        let valid_tcb_json = r#"{
            "tcbInfo": {
                "version": 3,
                "issueDate": "2024-01-01T00:00:00Z",
                "nextUpdate": "2024-02-01T00:00:00Z",
                "fmspc": "00906ED50000",
                "pceId": "0000",
                "tcbType": 0,
                "tcbEvaluationDataNumber": 12
            }
        }"#;

        let result: Result<TcbInfoResponse, _> = serde_json::from_str(valid_tcb_json);
        assert!(result.is_ok());
        let tcb_info = result.unwrap();
        assert_eq!(tcb_info.tcb_info.tcb_type, 0);
    }

    #[test]
    fn test_tcb_info_validation_invalid_type() {
        // Test invalid TCB info with tcbType = 1
        let invalid_tcb_json = r#"{
            "tcbInfo": {
                "version": 3,
                "tcbType": 1
            }
        }"#;

        let result: Result<TcbInfoResponse, _> = serde_json::from_str(invalid_tcb_json);
        assert!(result.is_ok());
        let tcb_info = result.unwrap();
        assert_eq!(tcb_info.tcb_info.tcb_type, 1);
    }

    #[test]
    fn test_tcb_info_missing_type_defaults_to_zero() {
        // Test TCB info without tcbType field (should default to 0)
        let missing_type_json = r#"{
            "tcbInfo": {
                "version": 3
            }
        }"#;

        let result: Result<TcbInfoResponse, _> = serde_json::from_str(missing_type_json);
        assert!(result.is_ok());
        let tcb_info = result.unwrap();
        assert_eq!(tcb_info.tcb_info.tcb_type, 0);
    }

    #[test]
    fn test_pck_cert_filtering() {
        // Test PCK certificate filtering
        let pck_certs_json = r#"[
            {
                "tcb": {"sgxtcbcomponents": []},
                "tcbm": "0000",
                "cert": "-----BEGIN CERTIFICATE-----\nMIICert1\n-----END CERTIFICATE-----"
            },
            {
                "tcb": {"sgxtcbcomponents": []},
                "tcbm": "0001",
                "cert": "Not available"
            },
            {
                "tcb": {"sgxtcbcomponents": []},
                "tcbm": "0002",
                "cert": "-----BEGIN CERTIFICATE-----\nMIICert2\n-----END CERTIFICATE-----"
            }
        ]"#;

        let parsed: Result<Vec<PckCertEntry>, _> = serde_json::from_str(pck_certs_json);
        assert!(parsed.is_ok());
        let certs = parsed.unwrap();
        assert_eq!(certs.len(), 3);

        // Verify we can identify "Not available" certificates
        let available_count = certs.iter().filter(|c| c.cert != "Not available").count();
        assert_eq!(available_count, 2);
    }
}
