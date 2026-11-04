// Copyright(c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

//! Intel PCS (Platform Certification Service) client: HTTP requests and validation of the
//! responses (PCK certificates, their issuer chain and TCB Info).

use crate::platform_data::is_fixed_len_hex;
use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::LazyLock;
use std::time::{Duration, Instant};
use tracing::{debug, error, info, instrument};
use url::Url;
use x509_parser::pem::Pem;
use x509_parser::prelude::{parse_x509_certificate, parse_x509_pem};
use x509_parser::x509::SubjectPublicKeyInfo;

/// Intel PCS API base URL (with trailing slash for proper join behavior).
const INTEL_PCS_API_BASE_URL: &str = "https://api.trustedservices.intel.com/sgx/certification/v4/";

static PCS_BASE_URL: LazyLock<Url> =
    LazyLock::new(|| Url::parse(INTEL_PCS_API_BASE_URL).expect("Invalid Intel PCS API base URL"));

/// Intel PCS API endpoint for PCK certificates with CPU SVN.
const INTEL_PCS_PCKCERTS_ENDPOINT: &str = "pckcerts/config";

/// Intel PCS API endpoint for TCB info (requires fmspc parameter).
const INTEL_PCS_TCB_ENDPOINT: &str = "tcb";

/// Intel PCS API endpoint for the Platform Composition Manifest (POST platformManifest).
const INTEL_PCS_PCM_ENDPOINT: &str = "pcm";

/// FMSPC (Family-Model-Stepping-Platform-CustomSKU) length: 6 bytes as hex.
pub const FMSPC_HEX_LEN: usize = 12;

/// Request body for Intel PCS API PCK certificates config endpoint.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct PckCertsRequest {
    pub platform_manifest: String,
    #[serde(rename = "pceid")]
    pub pce_id: String,
    #[serde(rename = "cpusvn")]
    pub cpu_svn: String,
}

/// Successful response from the PCK certificates endpoint.
#[derive(Debug)]
pub struct PckCertsResponse {
    /// Value of the `SGX-FMSPC` response header.
    pub fmspc: String,
    /// Value of the `SGX-PCK-Certificate-Issuer-Chain` response header
    /// (URL-encoded PEM chain).
    pub cert_chain: String,
    /// Raw JSON body (array of PCK certificate entries).
    pub pck_certs_json: String,
}

/// Successful response from the TCB info endpoint.
#[derive(Debug)]
pub struct TcbInfoResponse {
    /// Raw JSON body returned by the API.
    pub body: String,
    /// Value of the `TCB-Info-Issuer-Chain` response header
    /// (URL-encoded PEM chain: TCB Signing cert + Root CA).
    pub issuer_chain: String,
}

impl PckCertsRequest {
    /// Create from Kubernetes secret data
    pub fn from_secret_data(data: &BTreeMap<String, k8s_openapi::ByteString>) -> Result<Self> {
        let platform_manifest_bytes = data
            .get("platform_manifest")
            .context("Missing platform_manifest field")?;

        let pce_id_bytes = data.get("pce_id").context("Missing pce_id field")?;

        let cpu_svn_bytes = data.get("cpu_svn").context("Missing cpu_svn field")?;

        // Convert raw bytes to UTF-8 strings (hex-encoded data)
        let platform_manifest = String::from_utf8(platform_manifest_bytes.0.clone())
            .context("Invalid UTF-8 in platform_manifest")?;

        let pce_id =
            String::from_utf8(pce_id_bytes.0.clone()).context("Invalid UTF-8 in pce_id")?;

        let cpu_svn =
            String::from_utf8(cpu_svn_bytes.0.clone()).context("Invalid UTF-8 in cpu_svn")?;

        Ok(PckCertsRequest {
            platform_manifest,
            pce_id,
            cpu_svn,
        })
    }
}

/// Delay assumed when Intel PCS returns 429 without a usable `Retry-After` header.
pub const DEFAULT_RATE_LIMIT_RETRY_AFTER: Duration = Duration::from_secs(60);

/// Upper bound for a `Retry-After` delay requested by Intel PCS.
pub const MAX_RATE_LIMIT_RETRY_AFTER: Duration = Duration::from_secs(60 * 60);

/// Intel PCS rejected a request with 429 Too Many Requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PcsRateLimited {
    /// How long to wait before sending any further PCS requests.
    pub retry_after: Duration,
}

impl std::fmt::Display for PcsRateLimited {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Intel PCS API rate limit exceeded, retry after {}s",
            self.retry_after.as_secs()
        )
    }
}

impl std::error::Error for PcsRateLimited {}

/// Intel PCS rejected a request with an error status other than 429.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcsApiError {
    pub status: reqwest::StatusCode,
    pub error_code: String,
    pub error_message: String,
}

impl PcsApiError {
    /// Whether PCS rejected the request itself (4xx), so resending it unchanged won't help.
    pub fn is_client_error(&self) -> bool {
        self.status.is_client_error()
    }
}

impl std::fmt::Display for PcsApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Intel PCS API request failed: {} (Error-Code: {}, Error-Message: {})",
            self.status, self.error_code, self.error_message
        )
    }
}

impl std::error::Error for PcsApiError {}

/// Holds back all Intel PCS requests after PCS rate limited the registrar.
#[derive(Debug, Default)]
pub struct PcsPause {
    until: Option<Instant>,
}

impl PcsPause {
    /// Pauses PCS requests for `duration` from `now`; never shortens an existing pause.
    pub fn pause(&mut self, now: Instant, duration: Duration) {
        let until = now + duration;
        self.until = Some(self.until.map_or(until, |current| current.max(until)));
    }

    /// Returns the remaining pause, if any.
    pub fn remaining(&self, now: Instant) -> Option<Duration> {
        self.until
            .filter(|until| *until > now)
            .map(|until| until - now)
    }
}

/// Parses a `Retry-After` header value given in delta-seconds. Missing or unparsable values
/// (including the HTTP-date form) fall back to [`DEFAULT_RATE_LIMIT_RETRY_AFTER`]; the result is
/// capped at [`MAX_RATE_LIMIT_RETRY_AFTER`].
pub fn parse_retry_after(value: Option<&str>) -> Duration {
    value
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(DEFAULT_RATE_LIMIT_RETRY_AFTER)
        .min(MAX_RATE_LIMIT_RETRY_AFTER)
}

/// Handle Intel PCS API error response.
async fn handle_pcs_api_error(response: reqwest::Response, url: &str) -> anyhow::Error {
    let status = response.status();

    let rate_limited = (status == reqwest::StatusCode::TOO_MANY_REQUESTS).then(|| PcsRateLimited {
        retry_after: parse_retry_after(
            response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok()),
        ),
    });
    // Extract Intel PCS API error headers (v4 documentation) before consuming response
    let error_code = response
        .headers()
        .get("Error-Code")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("N/A")
        .to_string();

    let error_message = response
        .headers()
        .get("Error-Message")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("N/A")
        .to_string();

    let request_id = response
        .headers()
        .get("Request-ID")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("N/A")
        .to_string();

    let error_body = response
        .text()
        .await
        .unwrap_or_else(|_| "Unable to read error response".to_string());

    error!(
        url = %url,
        status = %status,
        error_code = %error_code,
        error_message = %error_message,
        request_id = %request_id,
        error_body = %error_body,
        "Intel PCS API Error"
    );

    if let Some(rate_limited) = rate_limited {
        return anyhow::Error::new(rate_limited);
    }

    anyhow::Error::new(PcsApiError {
        status,
        error_code,
        error_message,
    })
}

/// Fetch PCK Certificates.
#[instrument(skip(http_client, api_key, request_body))]
pub async fn fetch_pck_certs(
    http_client: &reqwest::Client,
    api_key: Option<&str>,
    request_body: &PckCertsRequest,
) -> Result<PckCertsResponse> {
    // Make POST request to Intel PCS API
    let url = PCS_BASE_URL
        .join(INTEL_PCS_PCKCERTS_ENDPOINT)
        .context("Failed to construct PCK certs URL")?;

    let mut request = http_client.post(url.as_str()).json(request_body);
    if let Some(key) = api_key {
        request = request.header("Ocp-Apim-Subscription-Key", key);
    }

    let response = request
        .send()
        .await
        .with_context(|| format!("HTTP POST to {url} failed"))?;

    // Check response status
    if !response.status().is_success() {
        return Err(handle_pcs_api_error(response, url.as_str()).await);
    }

    // Extract SGX-FMSPC and PCK certificate issuer chain headers
    let fmspc = response
        .headers()
        .get("SGX-FMSPC")
        .and_then(|v| v.to_str().ok())
        .context("Missing SGX-FMSPC header in response")?
        .to_string();
    validate_fmspc(&fmspc)?;

    let cert_chain = response
        .headers()
        .get("SGX-PCK-Certificate-Issuer-Chain")
        .and_then(|v| v.to_str().ok())
        .context("Missing SGX-PCK-Certificate-Issuer-Chain header")?
        .to_string();

    info!(fmspc = %fmspc, "Received PCK certificates");

    // Get PCK certificates JSON array from response body
    let pck_certs_json = response
        .text()
        .await
        .context("Failed to read PCK certs response body")?;

    Ok(PckCertsResponse {
        fmspc,
        cert_chain,
        pck_certs_json,
    })
}

/// Successful response from the Platform Composition Manifest (PCM) endpoint.
pub struct PcmResponse {
    /// Raw JSON body: the full signed PCM (`platformComposition`, `signature`,
    /// `issuerCertificateChain`).
    pub body: String,
    /// Value of the `PCM-Issuer-Chain` response header (URL-encoded PEM chain:
    /// PCM Signing cert + Root CA).
    pub issuer_chain: String,
}

/// Fetch the Platform Composition Manifest (PCM) for a multi-package platform.
///
/// Posts the platform manifest to Intel PCS and returns the full signed PCM JSON together with
/// the `PCM-Issuer-Chain` header needed to verify it.
#[instrument(skip(http_client, api_key, platform_manifest))]
pub async fn fetch_pcm(
    http_client: &reqwest::Client,
    api_key: Option<&str>,
    platform_manifest: &str,
) -> Result<PcmResponse> {
    let url = PCS_BASE_URL
        .join(INTEL_PCS_PCM_ENDPOINT)
        .context("Failed to construct PCM URL")?;

    let body = serde_json::json!({ "platformManifest": platform_manifest });
    let mut request = http_client.post(url.as_str()).json(&body);
    if let Some(key) = api_key {
        request = request.header("Ocp-Apim-Subscription-Key", key);
    }

    let response = request
        .send()
        .await
        .with_context(|| format!("HTTP POST to {url} failed"))?;

    if !response.status().is_success() {
        return Err(handle_pcs_api_error(response, url.as_str()).await);
    }

    let issuer_chain = response
        .headers()
        .get("PCM-Issuer-Chain")
        .and_then(|v| v.to_str().ok())
        .context("Missing PCM-Issuer-Chain header in PCM response")?
        .to_string();

    let body = response
        .text()
        .await
        .context("Failed to read PCM response body")?;

    info!("Received Platform Composition Manifest");

    Ok(PcmResponse { body, issuer_chain })
}

/// Validates an FMSPC value before it's used in the TCB Info query and as a label value.
pub fn validate_fmspc(fmspc: &str) -> Result<()> {
    anyhow::ensure!(
        is_fixed_len_hex::<FMSPC_HEX_LEN>(fmspc),
        "Invalid SGX-FMSPC: expected a {FMSPC_HEX_LEN}-character hex string, got {} bytes",
        fmspc.len()
    );
    Ok(())
}

/// Fetch SGX TCB Info using the FMSPC.
#[instrument(skip(http_client), fields(fmspc = %fmspc))]
pub async fn fetch_tcb_info(http_client: &reqwest::Client, fmspc: &str) -> Result<TcbInfoResponse> {
    validate_fmspc(fmspc)?;
    info!(fmspc = %fmspc, "Fetching SGX TCB Info");
    let mut tcb_url = PCS_BASE_URL
        .join(INTEL_PCS_TCB_ENDPOINT)
        .context("Failed to construct TCB URL")?;

    // Build query string with proper URL encoding
    tcb_url.set_query(Some(&format!(
        "fmspc={}&update=early",
        urlencoding::encode(fmspc)
    )));

    let response = http_client
        .get(tcb_url.as_str())
        .send()
        .await
        .with_context(|| format!("HTTP GET to {tcb_url} failed"))?;

    // Check TCB response status
    if !response.status().is_success() {
        return Err(handle_pcs_api_error(response, tcb_url.as_str()).await);
    }

    let issuer_chain = response
        .headers()
        .get("TCB-Info-Issuer-Chain")
        .and_then(|v| v.to_str().ok())
        .context("Missing TCB-Info-Issuer-Chain header in TCB info response")?
        .to_string();

    let body = response
        .text()
        .await
        .context("Failed to read TCB info response body")?;

    info!("Received SGX TCB Info");

    Ok(TcbInfoResponse { body, issuer_chain })
}

/// TCB Info structure for validation (partial - only fields we need)
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct TcbInfoDocument {
    tcb_info: TcbInfo,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct TcbInfo {
    #[serde(default)]
    tcb_type: u32,
    #[serde(default)]
    fmspc: String,
}

/// Signed TCB Info document as returned by Intel PCS. `tcb_info` keeps the raw JSON text,
/// since the signature covers those exact bytes.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct SignedTcbInfo<'a> {
    #[serde(borrow)]
    tcb_info: &'a serde_json::value::RawValue,
    signature: &'a str,
}

/// Length of an ECDSA P-256 signature in the fixed r||s encoding.
const ECDSA_P256_SIGNATURE_LEN: usize = 64;

/// Length of an ECDSA P-384 signature in the fixed r||s encoding.
const ECDSA_P384_SIGNATURE_LEN: usize = 96;

/// PCK Certificate entry from Intel PCS API response
#[derive(Deserialize, Serialize, Debug, Clone)]
struct PckCertEntry {
    tcb: serde_json::Value,
    tcbm: String,
    cert: String,
}

/// Verify a PCK certificate against the SGX Intermediate CA's public key
fn verify_certificate(cert_pem: &str, issuer_spki: &SubjectPublicKeyInfo<'_>) -> Result<bool> {
    let (_, pem) = parse_x509_pem(cert_pem.as_bytes())
        .map_err(|e| anyhow!("Failed to parse PCK certificate PEM: {e}"))?;
    let (_, cert) = parse_x509_certificate(&pem.contents)
        .map_err(|e| anyhow!("Failed to parse PCK certificate: {e}"))?;
    Ok(cert.verify_signature(Some(issuer_spki)).is_ok())
}

/// Decodes a URL-encoded PEM issuer chain as returned in Intel PCS response headers and
/// validates its structure: exactly two certificates, one self-signed Root CA and one
/// certificate signed by it. Returns `(root_der, issuer_der)`.
fn decode_and_validate_issuer_chain(chain: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    let decoded_chain = urlencoding::decode(chain).context("Failed to decode certificate chain")?;

    let mut chain_der: Vec<Vec<u8>> = Pem::iter_from_buffer(decoded_chain.as_bytes())
        .map(|r| {
            r.map(|pem| pem.contents)
                .context("Failed to parse PEM block in chain")
        })
        .collect::<Result<_>>()?;

    if chain_der.len() != 2 {
        bail!(
            "Invalid certificate chain: expected 2 certificates (Root CA + issuing CA), got {}",
            chain_der.len()
        );
    }

    // Root CA is self-signed (verifies against its own key)
    let (root_idx, issuer_idx) = {
        let (_, cert0) = parse_x509_certificate(&chain_der[0])
            .map_err(|e| anyhow!("Failed to parse certificate [0]: {e}"))?;
        let (_, cert1) = parse_x509_certificate(&chain_der[1])
            .map_err(|e| anyhow!("Failed to parse certificate [1]: {e}"))?;

        let cert0_self_signed = cert0.verify_signature(None).is_ok();
        let cert1_self_signed = cert1.verify_signature(None).is_ok();

        let (root_idx, issuer_idx, root_cert, issuer_cert) = if cert0_self_signed
            && !cert1_self_signed
        {
            (0, 1, &cert0, &cert1)
        } else if cert1_self_signed && !cert0_self_signed {
            (1, 0, &cert1, &cert0)
        } else {
            bail!(
                "Certificate chain validation failed: cannot identify self-signed root certificate"
            );
        };

        issuer_cert
            .verify_signature(Some(&root_cert.tbs_certificate.subject_pki))
            .context("Certificate chain validation failed: issuing CA is not signed by Root CA")?;

        (root_idx, issuer_idx)
    };
    debug!(root_idx, issuer_idx, "Certificate chain validated");

    let issuer_der = chain_der.swap_remove(issuer_idx);
    let root_der = chain_der.swap_remove(0);
    Ok((root_der, issuer_der))
}

/// Decodes a hex string of exactly `2 * N` characters into `N` bytes.
fn decode_hex<const N: usize>(s: &str) -> Result<[u8; N]> {
    anyhow::ensure!(
        s.len() == 2 * N && s.bytes().all(|b| b.is_ascii_hexdigit()),
        "expected a {}-character hex string",
        2 * N
    );
    let mut bytes = [0u8; N];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16)?;
    }
    Ok(bytes)
}

/// Verifies a hex-encoded, fixed-length `r||s` ECDSA signature over `body` against an uncompressed
/// EC `signer_public_key`, using the given ring verification algorithm. `SIG_LEN` is the expected
/// signature length in bytes (64 for P-256, 96 for P-384) and `collateral` names the signed object
/// for error messages. Intel's PCS collateral differs in curve: TCB Info/PCK use P-256/SHA-256
/// while the PCM uses P-384/SHA-384.
fn verify_fixed_ecdsa_signature<const SIG_LEN: usize>(
    algorithm: &'static dyn ring::signature::VerificationAlgorithm,
    signer_public_key: &[u8],
    body: &[u8],
    signature_hex: &str,
    collateral: &str,
) -> Result<()> {
    let signature = decode_hex::<SIG_LEN>(signature_hex)
        .with_context(|| format!("Invalid {collateral} signature encoding"))?;

    ring::signature::UnparsedPublicKey::new(algorithm, signer_public_key)
        .verify(body, &signature)
        .map_err(|_| anyhow!("{collateral} signature verification failed"))?;

    Ok(())
}

/// Filter out unavailable PCK certificates from an Intel PCS `/pckcerts` response and verify the
/// remaining ones against the issuer chain from the `SGX-PCK-Certificate-Issuer-Chain` header.
///
/// Returns the filtered certificates as JSON (certificates kept URL-encoded).
///
/// Note: the issuer chain is only checked for internal consistency (a self-signed Root CA that
/// signed the Intermediate CA, which signed every PCK certificate). The Root CA is not pinned to
/// the Intel SGX Root CA. This doesn't affect attestation integrity, since the PCK certificate
/// chain is embedded in quotes and verified against the Intel SGX Root CA during quote
/// verification, but a response with an unrelated chain is only detected at that point.
#[instrument(skip(pck_certs_json, cert_chain))]
pub fn filter_and_verify_pck_certs(pck_certs_json: &str, cert_chain: &str) -> Result<String> {
    // Parse the JSON array
    let pck_certs: Vec<PckCertEntry> =
        serde_json::from_str(pck_certs_json).context("Failed to parse PCK certificates JSON")?;

    debug!(total = pck_certs.len(), "Total PCK certificates received");

    // Validate the PCK issuer chain (Root CA -> Intermediate CA)
    let (_, intermediate_der) = decode_and_validate_issuer_chain(cert_chain)
        .context("Invalid PCK certificate issuer chain")?;
    let (_, intermediate_cert) = parse_x509_certificate(&intermediate_der)
        .map_err(|e| anyhow!("Failed to parse Intermediate CA certificate: {e}"))?;

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
                let preview = if entry.cert.chars().count() > 100 {
                    format!("{}...", entry.cert.chars().take(100).collect::<String>())
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

    Ok(filtered_json)
}

/// Validate the TCB Info JSON returned by Intel PCS. Only standard SGX TCB Info (`tcbType` 0)
/// is supported.
pub fn validate_tcb_info(tcb_info: &str) -> Result<()> {
    let parsed: TcbInfoDocument =
        serde_json::from_str(tcb_info).context("Failed to parse TCB Info JSON response")?;

    if parsed.tcb_info.tcb_type != 0 {
        bail!(
            "Invalid TCB Info: tcbType must be 0 (Standard SGX), got {}. \
             This tool only supports standard SGX TCB Info (tcbType=0).",
            parsed.tcb_info.tcb_type
        );
    }
    Ok(())
}

/// Verifies the ECDSA P-256/SHA-256 `signature` of a signed TCB Info JSON document
/// (`{"tcbInfo":{...},"signature":"<hex r||s>"}`) against the given uncompressed EC public key,
/// and checks that the signed `tcbInfo.fmspc` matches the requested FMSPC.
///
/// The signature covers the exact bytes of the `tcbInfo` object as returned by Intel PCS,
/// so the raw JSON text is verified rather than a re-serialization.
fn verify_tcb_info_signature(
    tcb_info_json: &str,
    signer_public_key: &[u8],
    expected_fmspc: &str,
) -> Result<()> {
    let signed: SignedTcbInfo<'_> =
        serde_json::from_str(tcb_info_json).context("Failed to parse signed TCB Info JSON")?;

    verify_fixed_ecdsa_signature::<ECDSA_P256_SIGNATURE_LEN>(
        &ring::signature::ECDSA_P256_SHA256_FIXED,
        signer_public_key,
        signed.tcb_info.get().as_bytes(),
        signed.signature,
        "TCB Info",
    )?;

    let tcb_info: TcbInfo = serde_json::from_str(signed.tcb_info.get())
        .context("Failed to parse signed tcbInfo object")?;
    if !tcb_info.fmspc.eq_ignore_ascii_case(expected_fmspc) {
        bail!(
            "TCB Info FMSPC mismatch: requested {expected_fmspc}, signed tcbInfo has {:?}",
            tcb_info.fmspc
        );
    }

    Ok(())
}

/// Verifies TCB Info returned by Intel PCS: the `TCB-Info-Issuer-Chain` must be a valid
/// Root CA -> TCB Signing chain rooted at the same Root CA as the PCK certificate issuer chain,
/// and the TCB Info signature must verify against the TCB Signing certificate.
pub fn verify_tcb_info(
    tcb_info_json: &str,
    tcb_issuer_chain: &str,
    pck_issuer_chain: &str,
    expected_fmspc: &str,
) -> Result<()> {
    let (tcb_root_der, signer_der) = decode_and_validate_issuer_chain(tcb_issuer_chain)
        .context("Invalid TCB Info issuer chain")?;
    let (pck_root_der, _) = decode_and_validate_issuer_chain(pck_issuer_chain)
        .context("Invalid PCK certificate issuer chain")?;

    if tcb_root_der != pck_root_der {
        bail!("TCB Info issuer chain Root CA does not match the PCK certificate issuer Root CA");
    }

    let (_, signer_cert) = parse_x509_certificate(&signer_der)
        .map_err(|e| anyhow!("Failed to parse TCB Signing certificate: {e}"))?;

    verify_tcb_info_signature(
        tcb_info_json,
        &signer_cert.public_key().subject_public_key.data,
        expected_fmspc,
    )
}

/// Signed Platform Composition Manifest as returned by Intel PCS. `platform_composition` keeps the
/// raw JSON text so the exact signed bytes are available.
#[derive(Deserialize)]
struct SignedPcm<'a> {
    #[serde(borrow, rename = "platformComposition")]
    platform_composition: &'a serde_json::value::RawValue,
    signature: &'a str,
}

/// Verify the PCM signature over the `platformComposition` body against the PCM Signing Key.
///
/// The signature is ECDSA over P-384 with SHA-384 in the fixed r||s encoding, computed over the raw
/// `platformComposition` body bytes. PCS returns compact JSON (no insignificant whitespace), so the
/// raw body is signed verbatim, the same way TCB Info is verified.
fn verify_pcm_signature(pcm_json: &str, signer_public_key: &[u8]) -> Result<()> {
    let signed: SignedPcm<'_> =
        serde_json::from_str(pcm_json).context("Failed to parse signed PCM JSON")?;

    verify_fixed_ecdsa_signature::<ECDSA_P384_SIGNATURE_LEN>(
        &ring::signature::ECDSA_P384_SHA384_FIXED,
        signer_public_key,
        signed.platform_composition.get().as_bytes(),
        signed.signature,
        "PCM",
    )
}

/// Verifies a Platform Composition Manifest returned by Intel PCS: the `PCM-Issuer-Chain` must be a
/// valid Root CA -> PCM Signing chain rooted at the same Root CA as the PCK certificate issuer
/// chain, and the PCM signature must verify against the PCM Signing certificate.
pub fn verify_pcm(pcm_json: &str, pcm_issuer_chain: &str, pck_issuer_chain: &str) -> Result<()> {
    let (pcm_root_der, signer_der) =
        decode_and_validate_issuer_chain(pcm_issuer_chain).context("Invalid PCM issuer chain")?;
    let (pck_root_der, _) = decode_and_validate_issuer_chain(pck_issuer_chain)
        .context("Invalid PCK certificate issuer chain")?;

    if pcm_root_der != pck_root_der {
        bail!("PCM issuer chain Root CA does not match the PCK certificate issuer Root CA");
    }

    let (_, signer_cert) = parse_x509_certificate(&signer_der)
        .map_err(|e| anyhow!("Failed to parse PCM Signing certificate: {e}"))?;

    verify_pcm_signature(pcm_json, &signer_cert.public_key().subject_public_key.data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_pcm_exposes_raw_platform_composition() {
        // Shape taken from the Intel PCS "Retrieve PCM V4" example response.
        let body = r#"{"platformComposition":{"id":"PCM","version":1,"platformInstanceId":"ABCDEABCDEABCDEABCDE012345678912","deviceIds":["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"]},"signature":"35e8b7","issuerCertificateChain":["MIICpj","MIICez"]}"#;

        let signed: SignedPcm<'_> = serde_json::from_str(body).expect("example PCM should parse");
        assert_eq!(signed.signature, "35e8b7");
        // The raw platformComposition text is preserved verbatim for signature verification.
        assert!(
            signed
                .platform_composition
                .get()
                .starts_with(r#"{"id":"PCM""#)
        );
    }

    #[test]
    fn signed_pcm_rejects_response_without_platform_composition() {
        assert!(serde_json::from_str::<SignedPcm>(r#"{"signature":"00"}"#).is_err());
    }

    #[test]
    fn pcs_pause() {
        let now = Instant::now();
        let mut pause = PcsPause::default();
        assert_eq!(pause.remaining(now), None);

        pause.pause(now, Duration::from_secs(30));
        assert_eq!(pause.remaining(now), Some(Duration::from_secs(30)));
        assert_eq!(pause.remaining(now + Duration::from_secs(30)), None);

        // A shorter pause doesn't shorten the current one, a longer one extends it
        pause.pause(now, Duration::from_secs(10));
        assert_eq!(pause.remaining(now), Some(Duration::from_secs(30)));
        pause.pause(now, Duration::from_secs(60));
        assert_eq!(pause.remaining(now), Some(Duration::from_secs(60)));
    }

    #[test]
    fn retry_after_parsing() {
        assert_eq!(parse_retry_after(Some("30")), Duration::from_secs(30));
        assert_eq!(parse_retry_after(Some(" 0 ")), Duration::ZERO);
        assert_eq!(parse_retry_after(None), DEFAULT_RATE_LIMIT_RETRY_AFTER);
        assert_eq!(
            parse_retry_after(Some("Wed, 21 Oct 2026 07:28:00 GMT")),
            DEFAULT_RATE_LIMIT_RETRY_AFTER
        );
        assert_eq!(
            parse_retry_after(Some("-5")),
            DEFAULT_RATE_LIMIT_RETRY_AFTER
        );
        assert_eq!(
            parse_retry_after(Some("99999999999")),
            MAX_RATE_LIMIT_RETRY_AFTER
        );
    }

    #[test]
    fn rate_limited_error_is_downcastable() {
        let err = anyhow::Error::new(PcsRateLimited {
            retry_after: Duration::from_secs(5),
        })
        .context("Failed to fetch PCK certificates");
        assert_eq!(
            err.downcast_ref::<PcsRateLimited>().map(|e| e.retry_after),
            Some(Duration::from_secs(5))
        );
    }

    #[test]
    fn fmspc_validation() {
        assert!(validate_fmspc("00906ED50000").is_ok());
        assert!(validate_fmspc("00906ed50000").is_ok());
        for bad in [
            "",
            "00906ED5000",
            "00906ED500000",
            "00906ED5000G",
            "00906ED5&x=1",
        ] {
            assert!(validate_fmspc(bad).is_err(), "{bad:?} accepted");
        }
    }

    #[test]
    fn test_validate_tcb_info() {
        assert!(validate_tcb_info(r#"{"tcbInfo":{"version":3,"tcbType":0}}"#).is_ok());
        assert!(validate_tcb_info(r#"{"tcbInfo":{"version":3}}"#).is_ok());
        assert!(validate_tcb_info(r#"{"tcbInfo":{"tcbType":1}}"#).is_err());
        assert!(validate_tcb_info(r#"{"tcbInfo":{"tcbType":-1}}"#).is_err());
        assert!(validate_tcb_info(r#"{"version":3}"#).is_err());
        assert!(validate_tcb_info("").is_err());
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

        let result: Result<TcbInfoDocument, _> = serde_json::from_str(valid_tcb_json);
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

        let result: Result<TcbInfoDocument, _> = serde_json::from_str(invalid_tcb_json);
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

        let result: Result<TcbInfoDocument, _> = serde_json::from_str(missing_type_json);
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

    const REAL_TCB_INFO: &str = include_str!("../testdata/tcb_info_00906ED50000.json");
    const REAL_TCB_CHAIN: &str = include_str!("../testdata/tcb_info_issuer_chain.txt");
    const REAL_PCK_CHAIN: &str = include_str!("../testdata/pck_issuer_chain.txt");
    const REAL_FMSPC: &str = "00906ED50000";

    #[test]
    fn test_verify_tcb_info_real_pcs_response() {
        verify_tcb_info(REAL_TCB_INFO, REAL_TCB_CHAIN, REAL_PCK_CHAIN, REAL_FMSPC)
            .expect("genuine TCB Info should verify");
        // FMSPC comparison is case-insensitive
        verify_tcb_info(
            REAL_TCB_INFO,
            REAL_TCB_CHAIN,
            REAL_PCK_CHAIN,
            &REAL_FMSPC.to_lowercase(),
        )
        .expect("genuine TCB Info should verify");
    }

    #[test]
    fn test_verify_tcb_info_rejects_tampered_body() {
        let tampered = REAL_TCB_INFO.replacen("\"tcbType\":0", "\"tcbType\":0 ", 1);
        assert_ne!(tampered, REAL_TCB_INFO);
        assert!(verify_tcb_info(&tampered, REAL_TCB_CHAIN, REAL_PCK_CHAIN, REAL_FMSPC).is_err());

        let tampered = REAL_TCB_INFO.replacen("\"OutOfDate\"", "\"UpToDate\"", 1);
        assert_ne!(tampered, REAL_TCB_INFO);
        assert!(verify_tcb_info(&tampered, REAL_TCB_CHAIN, REAL_PCK_CHAIN, REAL_FMSPC).is_err());
    }

    #[test]
    fn test_decode_hex() {
        assert_eq!(decode_hex::<2>("0aFf").unwrap(), [0x0a, 0xff]);
        for bad in ["0aF", "0aFf0", "0aFg", "+aFf", "0a\u{e9}"] {
            assert!(decode_hex::<2>(bad).is_err(), "{bad:?} accepted");
        }
    }

    #[test]
    fn test_verify_tcb_info_rejects_tampered_signature() {
        let idx = REAL_TCB_INFO.find("\"signature\":\"").unwrap() + "\"signature\":\"".len();
        let mut tampered = REAL_TCB_INFO.to_string();
        let flipped = if &tampered[idx..idx + 1] == "0" {
            "1"
        } else {
            "0"
        };
        tampered.replace_range(idx..idx + 1, flipped);
        assert!(verify_tcb_info(&tampered, REAL_TCB_CHAIN, REAL_PCK_CHAIN, REAL_FMSPC).is_err());

        let unsigned = REAL_TCB_INFO.replacen("\"signature\":", "\"sig\":", 1);
        assert!(verify_tcb_info(&unsigned, REAL_TCB_CHAIN, REAL_PCK_CHAIN, REAL_FMSPC).is_err());
    }

    #[test]
    fn test_verify_tcb_info_rejects_fmspc_mismatch() {
        assert!(
            verify_tcb_info(
                REAL_TCB_INFO,
                REAL_TCB_CHAIN,
                REAL_PCK_CHAIN,
                "00606A000000"
            )
            .is_err()
        );
    }

    #[test]
    fn test_verify_tcb_info_rejects_wrong_signer() {
        // PCK Processor CA chain is a valid Intel chain, but not the TCB Signing key
        assert!(
            verify_tcb_info(REAL_TCB_INFO, REAL_PCK_CHAIN, REAL_PCK_CHAIN, REAL_FMSPC).is_err()
        );
    }

    #[test]
    fn test_verify_tcb_info_rejects_invalid_chains() {
        let root_only = {
            let decoded = urlencoding::decode(REAL_TCB_CHAIN).unwrap();
            let last = decoded.rfind("-----BEGIN CERTIFICATE-----").unwrap();
            urlencoding::encode(&decoded[last..]).into_owned()
        };
        assert!(verify_tcb_info(REAL_TCB_INFO, &root_only, REAL_PCK_CHAIN, REAL_FMSPC).is_err());
        assert!(verify_tcb_info(REAL_TCB_INFO, "", REAL_PCK_CHAIN, REAL_FMSPC).is_err());
        assert!(verify_tcb_info(REAL_TCB_INFO, REAL_TCB_CHAIN, "", REAL_FMSPC).is_err());
    }
}
