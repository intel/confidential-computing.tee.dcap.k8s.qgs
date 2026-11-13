// Copyright(c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

//! Parsing and cryptographic validation of Intel PCS response payloads.

use crate::platform_data::is_fixed_len_hex;
use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, instrument};
use x509_parser::der_parser::{oid, oid::Oid, parse_der};
use x509_parser::pem::Pem;
use x509_parser::prelude::{parse_x509_certificate, parse_x509_pem};
use x509_parser::x509::SubjectPublicKeyInfo;

/// FMSPC (Family-Model-Stepping-Platform-CustomSKU) length: 6 bytes as hex.
pub const FMSPC_HEX_LEN: usize = 12;

/// OID for the Intel SGX PCK certificate extension.
const SGX_PCK_EXT_OID: Oid<'static> = oid!(1.2.840.113741.1.13.1);

/// OID for the Platform Instance ID (PIID) within the SGX PCK extension.
const SGX_PIID_OID: Oid<'static> = oid!(1.2.840.113741.1.13.1.6);

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

#[derive(Deserialize, Serialize, Debug, Clone)]
struct PckCertEntry {
    tcb: serde_json::Value,
    tcbm: String,
    cert: String,
}

fn verify_certificate(cert_pem: &str, issuer_spki: &SubjectPublicKeyInfo<'_>) -> Result<bool> {
    let (_, pem) = parse_x509_pem(cert_pem.as_bytes())
        .map_err(|error| anyhow!("Failed to parse PCK certificate PEM: {error}"))?;
    let (_, cert) = parse_x509_certificate(&pem.contents)
        .map_err(|error| anyhow!("Failed to parse PCK certificate: {error}"))?;
    Ok(cert.verify_signature(Some(issuer_spki)).is_ok())
}

fn extract_piid(pem: &str) -> Result<String> {
    let (_, pem_obj) =
        parse_x509_pem(pem.as_bytes()).map_err(|error| anyhow!("Failed to parse PEM: {error}"))?;
    let (_, cert) = parse_x509_certificate(&pem_obj.contents)
        .map_err(|error| anyhow!("Failed to parse certificate: {error}"))?;

    let ext = cert
        .get_extension_unique(&SGX_PCK_EXT_OID)
        .context("Duplicate SGX PCK extension in certificate")?
        .context("SGX PCK extension not found in certificate")?;

    let (_, outer) = parse_der(ext.value)
        .map_err(|error| anyhow!("Failed to parse SGX extension DER: {error}"))?;

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

            return Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect());
        }
    }

    bail!("PIID OID (1.2.840.113741.1.13.1.6) not found in SGX PCK extension")
}

/// Decodes a URL-encoded PEM issuer chain and validates its Root CA -> issuer structure.
fn decode_and_validate_issuer_chain(chain: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    let decoded_chain = urlencoding::decode(chain).context("Failed to decode certificate chain")?;

    let mut chain_der: Vec<Vec<u8>> = Pem::iter_from_buffer(decoded_chain.as_bytes())
        .map(|result| {
            result
                .map(|pem| pem.contents)
                .context("Failed to parse PEM block in chain")
        })
        .collect::<Result<_>>()?;

    if chain_der.len() != 2 {
        bail!(
            "Invalid certificate chain: expected 2 certificates (Root CA + issuing CA), got {}",
            chain_der.len()
        );
    }

    let (root_idx, issuer_idx) = {
        let (_, cert0) = parse_x509_certificate(&chain_der[0])
            .map_err(|error| anyhow!("Failed to parse certificate [0]: {error}"))?;
        let (_, cert1) = parse_x509_certificate(&chain_der[1])
            .map_err(|error| anyhow!("Failed to parse certificate [1]: {error}"))?;

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

fn decode_hex<const N: usize>(value: &str) -> Result<[u8; N]> {
    anyhow::ensure!(
        value.len() == 2 * N && value.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "expected a {}-character hex string",
        2 * N
    );
    let mut bytes = [0u8; N];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[2 * index..2 * index + 2], 16)?;
    }
    Ok(bytes)
}

/// Filters unavailable PCK certificates, verifies the remaining certificates, and extracts PIID.
///
/// The issuer chain is checked for internal consistency but its root is not pinned here. Quote
/// verification later validates the embedded PCK chain against the Intel SGX Root CA.
#[instrument(skip(pck_certs_json, cert_chain))]
pub(crate) fn filter_and_verify_pck_certs(
    pck_certs_json: &str,
    cert_chain: &str,
) -> Result<(String, String)> {
    let pck_certs: Vec<PckCertEntry> =
        serde_json::from_str(pck_certs_json).context("Failed to parse PCK certificates JSON")?;

    debug!(total = pck_certs.len(), "Total PCK certificates received");

    let (_, intermediate_der) = decode_and_validate_issuer_chain(cert_chain)
        .context("Invalid PCK certificate issuer chain")?;
    let (_, intermediate_cert) = parse_x509_certificate(&intermediate_der)
        .map_err(|error| anyhow!("Failed to parse Intermediate CA certificate: {error}"))?;
    let intermediate_spki = &intermediate_cert.tbs_certificate.subject_pki;

    let mut filtered_certs = Vec::new();
    let mut skipped_unavailable = 0;

    for (index, entry) in pck_certs.into_iter().enumerate() {
        if entry.cert == "Not available" {
            skipped_unavailable += 1;
            continue;
        }

        let decoded_cert = urlencoding::decode(&entry.cert)
            .with_context(|| format!("Failed to URL-decode certificate at index {index}"))?;

        match verify_certificate(&decoded_cert, intermediate_spki) {
            Ok(true) => filtered_certs.push(entry),
            Ok(false) => bail!("Certificate at index {index} failed signature verification"),
            Err(error) => {
                let preview = if entry.cert.chars().count() > 100 {
                    format!("{}...", entry.cert.chars().take(100).collect::<String>())
                } else {
                    entry.cert.clone()
                };
                bail!(
                    "Certificate at index {index} verification error: {error}\nCert preview: {preview}"
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

    let filtered_json = serde_json::to_string(&filtered_certs)
        .context("Failed to serialize filtered certificates")?;
    let first_cert_pem = urlencoding::decode(&filtered_certs[0].cert)
        .context("Failed to URL-decode first PCK certificate")?;
    let piid = extract_piid(&first_cert_pem)
        .context("Failed to extract PIID from first PCK certificate")?;

    Ok((filtered_json, piid))
}

/// Validates that PCS returned standard SGX TCB Info (`tcbType` 0).
pub(crate) fn validate_tcb_info(tcb_info: &str) -> Result<()> {
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

/// Verifies the TCB issuer chain, its root, and the signed TCB Info document.
pub(crate) fn verify_tcb_info(
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
        .map_err(|error| anyhow!("Failed to parse TCB Signing certificate: {error}"))?;

    verify_tcb_info_signature(
        tcb_info_json,
        &signer_cert.public_key().subject_public_key.data,
        expected_fmspc,
    )
}

/// Validates an FMSPC value before it's used in the TCB Info query and as a label value.
pub(crate) fn validate_fmspc(fmspc: &str) -> Result<()> {
    anyhow::ensure!(
        is_fixed_len_hex::<FMSPC_HEX_LEN>(fmspc),
        "Invalid SGX-FMSPC: expected a {FMSPC_HEX_LEN}-character hex string, got {} bytes",
        fmspc.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_standard_tcb_info() {
        assert!(validate_tcb_info(r#"{"tcbInfo":{"version":3,"tcbType":0}}"#).is_ok());
        assert!(validate_tcb_info(r#"{"tcbInfo":{"version":3}}"#).is_ok());
        assert!(validate_tcb_info(r#"{"tcbInfo":{"tcbType":1}}"#).is_err());
        assert!(validate_tcb_info(r#"{"tcbInfo":{"tcbType":-1}}"#).is_err());
        assert!(validate_tcb_info(r#"{"version":3}"#).is_err());
        assert!(validate_tcb_info("").is_err());
    }

    #[test]
    fn parses_pck_certificate_entries() {
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

        let certs: Vec<PckCertEntry> = serde_json::from_str(pck_certs_json).unwrap();
        assert_eq!(certs.len(), 3);
        assert_eq!(
            certs
                .iter()
                .filter(|cert| cert.cert != "Not available")
                .count(),
            2
        );
    }

    const REAL_TCB_INFO: &str = include_str!("../testdata/tcb_info_00906ED50000.json");
    const REAL_TCB_CHAIN: &str = include_str!("../testdata/tcb_info_issuer_chain.txt");
    const REAL_PCK_CHAIN: &str = include_str!("../testdata/pck_issuer_chain.txt");
    const REAL_FMSPC: &str = "00906ED50000";

    #[test]
    fn verifies_real_tcb_info_response() {
        verify_tcb_info(REAL_TCB_INFO, REAL_TCB_CHAIN, REAL_PCK_CHAIN, REAL_FMSPC).unwrap();
        verify_tcb_info(
            REAL_TCB_INFO,
            REAL_TCB_CHAIN,
            REAL_PCK_CHAIN,
            &REAL_FMSPC.to_lowercase(),
        )
        .unwrap();
    }

    #[test]
    fn rejects_tampered_tcb_info_body() {
        let tampered = REAL_TCB_INFO.replacen("\"tcbType\":0", "\"tcbType\":0 ", 1);
        assert!(verify_tcb_info(&tampered, REAL_TCB_CHAIN, REAL_PCK_CHAIN, REAL_FMSPC).is_err());

        let tampered = REAL_TCB_INFO.replacen("\"OutOfDate\"", "\"UpToDate\"", 1);
        assert!(verify_tcb_info(&tampered, REAL_TCB_CHAIN, REAL_PCK_CHAIN, REAL_FMSPC).is_err());
    }

    #[test]
    fn decodes_fixed_length_hex() {
        assert_eq!(decode_hex::<2>("0aFf").unwrap(), [0x0a, 0xff]);
        for bad in ["0aF", "0aFf0", "0aFg", "+aFf", "0a\u{e9}"] {
            assert!(decode_hex::<2>(bad).is_err(), "{bad:?} accepted");
        }
    }

    #[test]
    fn rejects_tampered_tcb_info_signature() {
        let index = REAL_TCB_INFO.find("\"signature\":\"").unwrap() + "\"signature\":\"".len();
        let mut tampered = REAL_TCB_INFO.to_string();
        let flipped = if &tampered[index..index + 1] == "0" {
            "1"
        } else {
            "0"
        };
        tampered.replace_range(index..index + 1, flipped);
        assert!(verify_tcb_info(&tampered, REAL_TCB_CHAIN, REAL_PCK_CHAIN, REAL_FMSPC).is_err());

        let unsigned = REAL_TCB_INFO.replacen("\"signature\":", "\"sig\":", 1);
        assert!(verify_tcb_info(&unsigned, REAL_TCB_CHAIN, REAL_PCK_CHAIN, REAL_FMSPC).is_err());
    }

    #[test]
    fn rejects_tcb_info_fmspc_mismatch() {
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
    fn rejects_wrong_tcb_info_signer() {
        assert!(
            verify_tcb_info(REAL_TCB_INFO, REAL_PCK_CHAIN, REAL_PCK_CHAIN, REAL_FMSPC).is_err()
        );
    }

    #[test]
    fn rejects_invalid_tcb_info_chains() {
        let root_only = {
            let decoded = urlencoding::decode(REAL_TCB_CHAIN).unwrap();
            let last = decoded.rfind("-----BEGIN CERTIFICATE-----").unwrap();
            urlencoding::encode(&decoded[last..]).into_owned()
        };
        assert!(verify_tcb_info(REAL_TCB_INFO, &root_only, REAL_PCK_CHAIN, REAL_FMSPC).is_err());
        assert!(verify_tcb_info(REAL_TCB_INFO, "", REAL_PCK_CHAIN, REAL_FMSPC).is_err());
        assert!(verify_tcb_info(REAL_TCB_INFO, REAL_TCB_CHAIN, "", REAL_FMSPC).is_err());
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
}
