// Copyright(c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

//! Intel PCS (Platform Certification Service) client: HTTP requests and validation of the
//! responses (PCK certificates, their issuer chain and TCB Info).

use crate::platform_data::is_fixed_len_hex;
use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::LazyLock;
use tracing::{debug, error, info, instrument};
use url::Url;
use x509_parser::der_parser::{oid, oid::Oid, parse_der};
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

/// Handle Intel PCS API error response.
async fn handle_pcs_api_error(response: reqwest::Response, url: &str) -> anyhow::Error {
    let status = response.status();

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

    anyhow::anyhow!(
        "Intel PCS API request failed: {status} (Error-Code: {error_code}, Error-Message: {error_message})"
    )
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

/// OID for the Intel SGX PCK certificate extension
const SGX_PCK_EXT_OID: Oid<'static> = oid!(1.2.840.113741.1.13.1);

/// OID for the Platform Instance ID (PIID) within the SGX PCK extension — 16-byte octet string
const SGX_PIID_OID: Oid<'static> = oid!(1.2.840.113741.1.13.1.6);

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

/// Filter out unavailable PCK certificates from an Intel PCS `/pckcerts` response, verify the
/// remaining ones against the issuer chain from the `SGX-PCK-Certificate-Issuer-Chain` header,
/// and extract the PIID from the first one.
///
/// Returns the filtered certificates as JSON (certificates kept URL-encoded) and the PIID.
///
/// Note: the issuer chain is only checked for internal consistency (a self-signed Root CA that
/// signed the Intermediate CA, which signed every PCK certificate). The Root CA is not pinned to
/// the Intel SGX Root CA. This doesn't affect attestation integrity, since the PCK certificate
/// chain is embedded in quotes and verified against the Intel SGX Root CA during quote
/// verification, but a response with an unrelated chain is only detected at that point.
#[instrument(skip(pck_certs_json, cert_chain))]
pub fn filter_and_verify_pck_certs(
    pck_certs_json: &str,
    cert_chain: &str,
) -> Result<(String, String)> {
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

    // Extract PIID from the topmost (first) certificate in the filtered list
    let first_cert_pem = urlencoding::decode(&filtered_certs[0].cert)
        .context("Failed to URL-decode first PCK certificate")?;
    let piid = extract_piid(&first_cert_pem)
        .context("Failed to extract PIID from first PCK certificate")?;

    Ok((filtered_json, piid))
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

    let signature = decode_hex::<ECDSA_P256_SIGNATURE_LEN>(signed.signature)
        .context("Invalid TCB Info signature encoding")?;

    ring::signature::UnparsedPublicKey::new(
        &ring::signature::ECDSA_P256_SHA256_FIXED,
        signer_public_key,
    )
    .verify(signed.tcb_info.get().as_bytes(), &signature)
    .map_err(|_| anyhow!("TCB Info signature verification failed"))?;

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

#[cfg(test)]
mod tests {
    use super::*;

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
