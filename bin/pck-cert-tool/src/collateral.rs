// Copyright(c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

//! Fetches the public Intel PCS collateral.

use crate::pcs_client::{
    ECDSA_P256_SIGNATURE_LEN, ENCLAVE_IDENTITY_ISSUER_CHAIN, FMSPC_HEX_LEN,
    PCK_CERTIFICATE_ISSUER_CHAIN, PCK_CRL_ISSUER_CHAIN, TCB_INFO_ISSUER_CHAIN,
    build_pcs_http_client, decode_and_validate_issuer_chain, send_pcs_request,
    send_pcs_request_allowing_status, verify_tcb_info,
};
use anyhow::{Context, Result, anyhow, bail};
use clap::ValueEnum;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use tracing::{info, instrument};
use url::Url;
use x509_parser::extensions::{DistributionPointName, GeneralName, ParsedExtension};
use x509_parser::prelude::{parse_x509_certificate, parse_x509_crl};

const PCS_API_VERSION: u8 = 4;

/// E5 - multi-socket server platforms supporting DCAP attestation (examples include but may not be limited to: Intel® Xeon® D and Intel® Xeon® Scalable)
const FMSPC_PLATFORM_TYPE: &str = "E5";

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum TcbUpdateType {
    #[value(name = "standard")]
    Standard,
    #[value(name = "early")]
    Early,
    #[value(name = "all")]
    All,
}

impl TcbUpdateType {
    fn updates(self) -> &'static [&'static str] {
        match self {
            Self::Standard => &["standard"],
            Self::Early => &["early"],
            Self::All => &["standard", "early"],
        }
    }
}

pub fn parse_fmspc(value: &str) -> std::result::Result<String, String> {
    if value.len() != FMSPC_HEX_LEN || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!(
            "invalid FMSPC {value:?}: expected exactly {FMSPC_HEX_LEN} hexadecimal characters"
        ));
    }
    Ok(value.to_ascii_uppercase())
}

#[derive(Debug)]
struct PckCrlResponse {
    body: Vec<u8>,
    issuer_chain: String,
}

#[derive(Debug)]
struct SignedJsonResponse {
    body: String,
    issuer_chain: String,
}

#[derive(Debug, Deserialize)]
struct FmspcResponse {
    fmspc: String,
}

fn header(response: &reqwest::Response, name: &str) -> Result<String> {
    response
        .headers()
        .get(name)
        .with_context(|| format!("PCS response is missing {name}"))?
        .to_str()
        .with_context(|| format!("PCS response header {name} is not valid text"))
        .map(str::to_owned)
}

async fn fetch_pck_crl(
    http_client: &reqwest::Client,
    base_url: &Url,
    ca: &str,
) -> Result<PckCrlResponse> {
    let mut url = base_url.join("pckcrl")?;
    url.query_pairs_mut()
        .append_pair("ca", ca)
        .append_pair("encoding", "der");
    let response = send_pcs_request(http_client, http_client.get(url.clone())).await?;
    let issuer_chain = header(&response, PCK_CRL_ISSUER_CHAIN)?;
    let body = response.bytes().await?.to_vec();
    Ok(PckCrlResponse { body, issuer_chain })
}

async fn fetch_signed_json(
    http_client: &reqwest::Client,
    url: &Url,
    issuer_chain_header: &str,
) -> Result<SignedJsonResponse> {
    let response = send_pcs_request(http_client, http_client.get(url.clone())).await?;
    let issuer_chain = header(&response, issuer_chain_header)?;
    let body = response.text().await?;
    serde_json::from_str::<Value>(&body).context("PCS returned invalid collateral JSON")?;
    Ok(SignedJsonResponse { body, issuer_chain })
}

async fn fetch_optional_signed_json(
    http_client: &reqwest::Client,
    url: &Url,
    issuer_chain_header: &str,
) -> Result<Option<SignedJsonResponse>> {
    let response = send_pcs_request_allowing_status(
        http_client,
        http_client.get(url.clone()),
        reqwest::StatusCode::NOT_FOUND,
    )
    .await?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    let issuer_chain = header(&response, issuer_chain_header)?;
    let body = response.text().await?;
    serde_json::from_str::<Value>(&body).context("PCS returned invalid collateral JSON")?;
    Ok(Some(SignedJsonResponse { body, issuer_chain }))
}

fn parse_fmspcs_response(body: &str) -> Result<Vec<String>> {
    let entries: Vec<FmspcResponse> =
        serde_json::from_str(body).context("PCS returned an invalid FMSPC list")?;
    let fmspcs = entries
        .into_iter()
        .map(|entry| {
            parse_fmspc(&entry.fmspc)
                .map_err(|error| anyhow!("PCS returned an invalid FMSPC: {error}"))
        })
        .collect::<Result<Vec<_>>>()?;
    if fmspcs.is_empty() {
        bail!("PCS returned an empty FMSPC list for platform=all");
    }
    Ok(fmspcs)
}

async fn fetch_fmspcs(http_client: &reqwest::Client, base_url: &Url) -> Result<Vec<String>> {
    let mut url = base_url.join("fmspcs")?;
    url.query_pairs_mut()
        .append_pair("platform", FMSPC_PLATFORM_TYPE);
    let body = send_pcs_request(http_client, http_client.get(url))
        .await?
        .text()
        .await?;
    parse_fmspcs_response(&body)
        .with_context(|| format!("failed to fetch FMSPCs for platform={FMSPC_PLATFORM_TYPE}"))
}

fn verify_crl(crl_der: &[u8], signer_der: &[u8], description: &str) -> Result<()> {
    let (_, signer) = parse_x509_certificate(signer_der)
        .map_err(|error| anyhow!("failed to parse {description} signer certificate: {error}"))?;
    let (_, crl) = parse_x509_crl(crl_der)
        .map_err(|error| anyhow!("failed to parse {description}: {error}"))?;
    crl.verify_signature(&signer.tbs_certificate.subject_pki)
        .with_context(|| format!("{description} signature verification failed"))
}

fn root_crl_url(root_der: &[u8]) -> Result<String> {
    let (_, root) = parse_x509_certificate(root_der)
        .map_err(|error| anyhow!("failed to parse Intel SGX Root CA certificate: {error}"))?;

    for extension in root.extensions() {
        if let ParsedExtension::CRLDistributionPoints(points) = extension.parsed_extension() {
            for point in points.iter() {
                if let Some(DistributionPointName::FullName(names)) = &point.distribution_point {
                    for name in names {
                        if let GeneralName::URI(uri) = name {
                            return Ok((*uri).to_owned());
                        }
                    }
                }
            }
        }
    }

    bail!("Intel SGX Root CA certificate has no CRL distribution point URI")
}

fn tdx_base_url(sgx_base_url: &Url) -> Result<Url> {
    let path = sgx_base_url.path();
    let tdx_path = path.replace("/sgx/", "/tdx/").replace("/sgx", "/tdx");
    if tdx_path == path {
        bail!("PCS base URL path must contain an SGX component");
    }
    let mut url = sgx_base_url.clone();
    url.set_path(&tdx_path);
    Ok(url)
}

fn update_url(base_url: &Url, path: &str, update: &str) -> Result<Url> {
    let mut url = base_url.join(path)?;
    url.query_pairs_mut().append_pair("update", update);
    Ok(url)
}

fn ensure_consistent_chain(
    current: &mut Option<String>,
    new_chain: &str,
    name: &str,
) -> Result<()> {
    if current
        .as_ref()
        .is_some_and(|existing| existing != new_chain)
    {
        bail!("PCS returned inconsistent {name} issuer chains");
    }
    current.get_or_insert_with(|| new_chain.to_owned());
    Ok(())
}

fn verified_tcb_info_value(
    response: &SignedJsonResponse,
    pck_issuer_chain: &str,
    fmspc: &str,
) -> Result<Value> {
    verify_tcb_info(
        &response.body,
        &response.issuer_chain,
        pck_issuer_chain,
        fmspc,
    )?;
    let value = serde_json::from_str::<Value>(&response.body)?;
    let serialized = serde_json::to_string(&value)?;
    verify_tcb_info(&serialized, &response.issuer_chain, pck_issuer_chain, fmspc)
        .context("serialized TCB Info no longer matches its PCS signature")?;
    Ok(value)
}

fn verified_identity_value(response: &SignedJsonResponse, pck_issuer_chain: &str) -> Result<Value> {
    verify_enclave_identity(&response.body, &response.issuer_chain, pck_issuer_chain)?;
    let value = serde_json::from_str::<Value>(&response.body)?;
    let serialized = serde_json::to_string(&value)?;
    verify_enclave_identity(&serialized, &response.issuer_chain, pck_issuer_chain)
        .context("serialized enclave identity no longer matches its PCS signature")?;
    Ok(value)
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct SignedEnclaveIdentity<'a> {
    #[serde(borrow)]
    enclave_identity: &'a serde_json::value::RawValue,
    signature: &'a str,
}

fn verify_enclave_identity(
    identity_json: &str,
    identity_issuer_chain: &str,
    pck_issuer_chain: &str,
) -> Result<()> {
    let signed: SignedEnclaveIdentity<'_> =
        serde_json::from_str(identity_json).context("Failed to parse signed enclave identity")?;
    let signature = crate::pcs_client::decode_hex::<ECDSA_P256_SIGNATURE_LEN>(signed.signature)
        .context("Invalid enclave identity signature encoding")?;

    let (identity_root_der, signer_der) = decode_and_validate_issuer_chain(identity_issuer_chain)
        .context("Invalid enclave identity issuer chain")?;
    let (pck_root_der, _) = decode_and_validate_issuer_chain(pck_issuer_chain)
        .context("Invalid PCK certificate issuer chain")?;
    if identity_root_der != pck_root_der {
        bail!("Enclave identity issuer chain Root CA does not match PCK issuer chain Root CA");
    }

    let (_, signer_cert) = parse_x509_certificate(&signer_der)
        .map_err(|e| anyhow!("Failed to parse enclave identity signing certificate: {e}"))?;
    ring::signature::UnparsedPublicKey::new(
        &ring::signature::ECDSA_P256_SHA256_FIXED,
        &signer_cert.public_key().subject_public_key.data,
    )
    .verify(signed.enclave_identity.get().as_bytes(), &signature)
    .map_err(|_| anyhow!("Enclave identity signature verification failed"))
}

fn initial_output() -> Value {
    json!({
        "platforms": [],
        "collaterals": {
            "version": PCS_API_VERSION,
            "pck_certs": [],
            "tcbinfos": [],
            "pckcacrl": {},
            "qeidentity": "",
            "tdqeidentity": "",
            "qveidentity": "",
            "certificates": {
                PCK_CERTIFICATE_ISSUER_CHAIN: {},
                TCB_INFO_ISSUER_CHAIN: "",
                ENCLAVE_IDENTITY_ISSUER_CHAIN: "",
            },
            "rootcacrl": "",
        }
    })
}

fn remove_empty_identity_placeholders(output: &mut Value) {
    let Some(collaterals) = output["collaterals"].as_object_mut() else {
        return;
    };
    for key in ["qeidentity", "tdqeidentity", "qveidentity"] {
        if collaterals.get(key) == Some(&Value::String(String::new())) {
            collaterals.remove(key);
        }
    }
}

#[instrument(skip(fmspcs, output_file))]
pub async fn fetch_collateral(
    fmspcs: Vec<String>,
    tcb_update_type: TcbUpdateType,
    output_file: PathBuf,
) -> Result<()> {
    let base_url = crate::pcs_client::PCS_BASE_URL.clone();
    let tdx_url = tdx_base_url(&base_url)?;
    let http_client = build_pcs_http_client()?;
    let mut output = initial_output();
    let fmspcs = if fmspcs.is_empty() {
        info!(platform = FMSPC_PLATFORM_TYPE, "Fetching Intel PCS FMSPCs");
        fetch_fmspcs(&http_client, &base_url).await?
    } else {
        fmspcs
    };

    info!("Fetching Intel PCS processor and platform CRLs");
    let processor_crl = fetch_pck_crl(&http_client, &base_url, "processor").await?;
    let platform_crl = fetch_pck_crl(&http_client, &base_url, "platform").await?;

    let (root_der, processor_ca_der) =
        decode_and_validate_issuer_chain(&processor_crl.issuer_chain)
            .context("invalid processor PCK CRL issuer chain")?;
    let (platform_root_der, platform_ca_der) =
        decode_and_validate_issuer_chain(&platform_crl.issuer_chain)
            .context("invalid platform PCK CRL issuer chain")?;
    if root_der != platform_root_der {
        bail!("processor and platform PCK CRL issuer chains have different roots");
    }
    verify_crl(&processor_crl.body, &processor_ca_der, "processor PCK CRL")?;
    verify_crl(&platform_crl.body, &platform_ca_der, "platform PCK CRL")?;

    let root_crl_cdp = root_crl_url(&root_der)?;
    let root_crl_url = Url::parse(&root_crl_cdp)?;
    let root_crl = send_pcs_request(&http_client, http_client.get(root_crl_url))
        .await?
        .bytes()
        .await?
        .to_vec();
    verify_crl(&root_crl, &root_der, "root CA CRL")?;

    let mut tcbinfos = Vec::new();
    let mut tcb_issuer_chain = None;
    for fmspc in BTreeSet::from_iter(fmspcs) {
        info!(%fmspc, "Fetching Intel TDX TCB info");

        let mut tcbinfo = Map::new();
        tcbinfo.insert("fmspc".into(), Value::String(fmspc.clone()));
        for update in tcb_update_type.updates() {
            let key_suffix = if *update == "early" { "_early" } else { "" };

            let mut tdx_tcb_url = tdx_url.join("tcb")?;
            tdx_tcb_url
                .query_pairs_mut()
                .append_pair("fmspc", &fmspc)
                .append_pair("update", update);
            if let Some(tdx_tcb) =
                fetch_optional_signed_json(&http_client, &tdx_tcb_url, TCB_INFO_ISSUER_CHAIN)
                    .await?
            {
                let tdx_tcb_value =
                    verified_tcb_info_value(&tdx_tcb, &processor_crl.issuer_chain, &fmspc)?;
                ensure_consistent_chain(&mut tcb_issuer_chain, &tdx_tcb.issuer_chain, "TCB Info")?;
                tcbinfo.insert(format!("tdx_tcbinfo{key_suffix}"), tdx_tcb_value);
            }
        }
        if tcbinfo.len() > 1 {
            tcbinfos.push(Value::Object(tcbinfo));
        }
    }

    let mut enclave_issuer_chain = None;
    for update in tcb_update_type.updates() {
        info!(update, "Fetching Intel TDQE identity");
        let url = update_url(&tdx_url, "qe/identity", update)?;
        let identity = fetch_signed_json(&http_client, &url, ENCLAVE_IDENTITY_ISSUER_CHAIN).await?;
        let identity_value = verified_identity_value(&identity, &processor_crl.issuer_chain)?;
        ensure_consistent_chain(
            &mut enclave_issuer_chain,
            &identity.issuer_chain,
            "enclave identity",
        )?;
        let key_suffix = if *update == "early" { "_early" } else { "" };
        output["collaterals"][format!("tdqeidentity{key_suffix}")] = identity_value;
    }

    let mut pck_chains = Map::new();
    pck_chains.insert(
        "PROCESSOR".into(),
        Value::String(processor_crl.issuer_chain),
    );
    pck_chains.insert("PLATFORM".into(), Value::String(platform_crl.issuer_chain));

    output["collaterals"]["tcbinfos"] = Value::Array(tcbinfos);
    output["collaterals"]["pckcacrl"] = json!({
        "processorCrl": hex::encode(&processor_crl.body),
        "platformCrl": hex::encode(&platform_crl.body),
    });
    output["collaterals"]["certificates"][PCK_CERTIFICATE_ISSUER_CHAIN] = Value::Object(pck_chains);
    output["collaterals"]["certificates"][TCB_INFO_ISSUER_CHAIN] =
        Value::String(tcb_issuer_chain.context("missing TCB Info issuer chain")?);
    output["collaterals"]["certificates"][ENCLAVE_IDENTITY_ISSUER_CHAIN] =
        Value::String(enclave_issuer_chain.context("missing enclave identity issuer chain")?);
    output["collaterals"]["rootcacrl_cdp"] = Value::String(root_crl_cdp);
    output["collaterals"]["rootcacrl"] = Value::String(hex::encode(&root_crl));
    remove_empty_identity_placeholders(&mut output);

    let encoded = serde_json::to_string(&output).context("failed to serialize collateral JSON")?;
    fs::write(&output_file, encoded)
        .with_context(|| format!("failed to write collateral file {}", output_file.display()))?;
    info!(path = %output_file.display(), "PCS collateral written successfully");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_and_normalizes_fmspc() {
        assert_eq!(parse_fmspc("00906ed50000"), Ok("00906ED50000".into()));
        assert!(parse_fmspc("00906ED5000").is_err());
        assert!(parse_fmspc("00906ED5000Z").is_err());
    }

    #[test]
    fn initializes_python_compatible_empty_values() {
        let output = initial_output();
        let collaterals = &output["collaterals"];

        assert_eq!(output["platforms"], json!([]));
        assert_eq!(collaterals["pck_certs"], json!([]));
        assert_eq!(collaterals["tcbinfos"], json!([]));
        assert_eq!(collaterals["pckcacrl"], json!({}));
        assert_eq!(collaterals["qeidentity"], json!(""));
        assert_eq!(collaterals["tdqeidentity"], json!(""));
        assert_eq!(collaterals["qveidentity"], json!(""));
        assert_eq!(
            collaterals["certificates"][PCK_CERTIFICATE_ISSUER_CHAIN],
            json!({})
        );
        assert_eq!(
            collaterals["certificates"][TCB_INFO_ISSUER_CHAIN],
            json!("")
        );
        assert_eq!(
            collaterals["certificates"][ENCLAVE_IDENTITY_ISSUER_CHAIN],
            json!("")
        );
        assert_eq!(collaterals["rootcacrl"], json!(""));
        assert!(collaterals.get("rootcacrl_cdp").is_none());
    }

    #[test]
    fn parses_and_normalizes_fmspc_list() {
        let body = r#"[
            {"fmspc":"00906ED50000","platform":"client"},
            {"fmspc":"00A06D080000","platform":"E5"}
        ]"#;

        assert_eq!(
            parse_fmspcs_response(body).unwrap(),
            vec!["00906ED50000", "00A06D080000"]
        );
        assert!(parse_fmspcs_response("[]").is_err());
        assert!(parse_fmspcs_response(r#"[{"fmspc":"invalid"}]"#).is_err());
    }

    #[test]
    fn preserves_signed_tcb_info_member_order() {
        let body = r#"{"tcbInfo":{"id":"SGX","version":3,"issueDate":"2026-11-19T13:35:38Z","nextUpdate":"2026-12-19T13:35:38Z","fmspc":"f0806f000000","pceId":"0000","tcbType":0},"signature":"0123456789abcdef"}"#;
        let parsed: Value = serde_json::from_str(body).unwrap();

        assert_eq!(serde_json::to_string(&parsed).unwrap(), body);
    }

    #[test]
    fn removes_only_unfetched_identity_placeholders() {
        let mut output = initial_output();
        output["collaterals"]["qeidentity_early"] = json!({"enclaveIdentity": {}});

        remove_empty_identity_placeholders(&mut output);

        let collaterals = output["collaterals"].as_object().unwrap();
        assert!(!collaterals.contains_key("qeidentity"));
        assert!(!collaterals.contains_key("tdqeidentity"));
        assert!(!collaterals.contains_key("qveidentity"));
        assert!(collaterals.contains_key("qeidentity_early"));
    }
}
