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

    let body = response
        .text()
        .await
        .context("Failed to read TCB info response body")?;

    info!("Received SGX TCB Info");

    Ok(TcbInfoResponse { body })
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
}

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
}
