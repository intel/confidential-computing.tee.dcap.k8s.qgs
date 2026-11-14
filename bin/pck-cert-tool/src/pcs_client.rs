// Copyright(c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

//! Intel PCS (Platform Certification Service) HTTP client and request orchestration.

use crate::cache::build_cache_blob;
use crate::pcs_response_validation::{
    filter_and_verify_pck_certs, validate_fmspc, validate_tcb_info, verify_tcb_info,
};
use anyhow::{Context, Result};
use serde::Serialize;
use std::collections::BTreeMap;
use std::sync::LazyLock;
use std::time::{Duration, Instant};
use tracing::{debug, error, info, instrument};
use url::Url;

/// Intel PCS API base URL (with trailing slash for proper join behavior).
const INTEL_PCS_API_BASE_URL: &str = "https://api.trustedservices.intel.com/sgx/certification/v4/";

static PCS_BASE_URL: LazyLock<Url> =
    LazyLock::new(|| Url::parse(INTEL_PCS_API_BASE_URL).expect("Invalid Intel PCS API base URL"));

/// Intel PCS API endpoint for PCK certificates with CPU SVN.
const INTEL_PCS_PCKCERTS_ENDPOINT: &str = "pckcerts/config";

/// Intel PCS API endpoint for TCB info (requires fmspc parameter).
const INTEL_PCS_TCB_ENDPOINT: &str = "tcb";

/// Connection timeout for Intel PCS API requests.
const PCS_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Overall per-request timeout for Intel PCS API requests.
const PCS_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

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

/// Builds the shared HTTP client used by all PCS registration modes.
pub fn build_pcs_http_client() -> Result<reqwest::Client> {
    // Create HTTP client for Intel PCS API with retry on connection errors and 5xx.
    // 429 is not retried here: it pauses all PCS requests for the Retry-After delay instead.
    let retry_policy = reqwest::retry::for_host("api.trustedservices.intel.com")
        .max_retries_per_request(3)
        .classify_fn(|req_rep| {
            let retryable = req_rep.error().is_some()
                || req_rep
                    .status()
                    .map(|s| s.is_server_error())
                    .unwrap_or(false);
            if retryable {
                req_rep.retryable()
            } else {
                req_rep.success()
            }
        });

    reqwest::Client::builder()
        .retry(retry_policy)
        .connect_timeout(PCS_CONNECT_TIMEOUT)
        .timeout(PCS_REQUEST_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("Failed to build Intel PCS HTTP client")
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
async fn fetch_pck_certs(
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

/// Fetch SGX TCB Info using the FMSPC.
#[instrument(skip(http_client), fields(fmspc = %fmspc))]
async fn fetch_tcb_info(http_client: &reqwest::Client, fmspc: &str) -> Result<TcbInfoResponse> {
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

/// Verified PCS response encoded for the local QPL cache.
#[derive(Debug)]
pub struct PlatformCache {
    pub fmspc: String,
    pub cache_data: Vec<u8>,
    pub piid: String,
    pub expiration_time: u64,
}

/// Fetches and verifies all PCS data needed to build a QPL cache blob.
pub async fn fetch_platform_cache(
    http_client: &reqwest::Client,
    api_key: Option<&str>,
    request_body: &PckCertsRequest,
) -> Result<PlatformCache> {
    // Fetch PCK certificates from Intel PCS API
    let pck_response = fetch_pck_certs(http_client, api_key, request_body).await?;
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
    validate_tcb_info(&tcb_info)?;
    debug!("TCB Info validation passed (tcbType=0)");

    debug!("Verifying TCB Info signature");
    verify_tcb_info(
        &tcb_info,
        &tcb_info_response.issuer_chain,
        &cert_chain,
        &fmspc,
    )?;

    let (cache_data, expiration_time) = build_cache_blob(
        &request_body.cpu_svn,
        &tcb_info,
        &cert_chain,
        &filtered_pck_certs_json,
    )?;

    Ok(PlatformCache {
        fmspc,
        cache_data,
        piid,
        expiration_time,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
