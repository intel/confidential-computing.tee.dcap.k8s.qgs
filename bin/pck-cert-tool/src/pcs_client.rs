// Copyright(c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

//! Intel PCS (Platform Certification Service) HTTP client.

use anyhow::{Context, Result};
use serde::Serialize;
use std::collections::BTreeMap;
use std::sync::LazyLock;
use tracing::{error, info, instrument};
use url::Url;

/// Intel PCS API base URL (with trailing slash for proper join behavior).
const INTEL_PCS_API_BASE_URL: &str = "https://api.trustedservices.intel.com/sgx/certification/v4/";

static PCS_BASE_URL: LazyLock<Url> =
    LazyLock::new(|| Url::parse(INTEL_PCS_API_BASE_URL).expect("Invalid Intel PCS API base URL"));

/// Intel PCS API endpoint for PCK certificates with CPU SVN.
const INTEL_PCS_PCKCERTS_ENDPOINT: &str = "pckcerts/config";

/// Intel PCS API endpoint for TCB info (requires fmspc parameter).
const INTEL_PCS_TCB_ENDPOINT: &str = "tcb";

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
    pub(crate) fn from_secret_data(
        data: &BTreeMap<String, k8s_openapi::ByteString>,
    ) -> Result<Self> {
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

    // Extract SGX-FMSPC and certificate chain headers
    let fmspc = response
        .headers()
        .get("SGX-FMSPC")
        .and_then(|v| v.to_str().ok())
        .context("Missing SGX-FMSPC header in response")?
        .to_string();

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

/// Fetch SGX TCB Info using the FMSPC.
#[instrument(skip(http_client), fields(fmspc = %fmspc))]
pub async fn fetch_tcb_info(http_client: &reqwest::Client, fmspc: &str) -> Result<TcbInfoResponse> {
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
