// Copyright(c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

//! Validation of `type=platform-data` secrets consumed by the registrar.
//!
//! These secrets are written by the `get-platforms` init container on every node, so the
//! registrar treats their contents as untrusted and validates them before using them to name
//! Kubernetes objects or sending them to Intel PCS.

use crate::pcs_client::PckCertsRequest;
use anyhow::{Result, ensure};
use k8s_openapi::ByteString;
use std::collections::BTreeMap;

/// Length, in hex characters, of a QE ID (sgx_key_128bit_t is 16 bytes).
pub const QE_ID_HEX_LEN: usize = 32;

/// Length, in hex characters, of a CPU SVN (16 bytes).
pub const CPU_SVN_HEX_LEN: usize = 32;

/// Length, in hex characters, of a PCE ID (2 bytes).
pub const PCE_ID_HEX_LEN: usize = 4;

/// Maximum length, in hex characters, of a platform manifest. The EFI variable header encodes
/// the manifest size as a `u16`, so its hex encoding can never be longer than this.
pub const PLATFORM_MANIFEST_MAX_HEX_LEN: usize = u16::MAX as usize * 2;

/// Returns true if `value` consists of exactly `N` ASCII hex digits.
pub fn is_fixed_len_hex<const N: usize>(value: &str) -> bool {
    value.len() == N && value.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Returns a stable fingerprint (`sha256:<hex>`) of the registration inputs sent to Intel PCS.
///
/// The registrar records it on the PCK secret so that platform-data secret updates which don't
/// change the PCS request (e.g. label/annotation edits) don't trigger new PCS calls.
pub fn registration_fingerprint(request: &PckCertsRequest) -> String {
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    // Length-prefix each field so that field boundaries are unambiguous
    for field in [
        &request.platform_manifest,
        &request.pce_id,
        &request.cpu_svn,
    ] {
        ctx.update(&(field.len() as u64).to_le_bytes());
        ctx.update(field.as_bytes());
    }
    let digest = ctx.finish();
    let hex: String = digest.as_ref().iter().map(|b| format!("{b:02x}")).collect();
    format!("sha256:{hex}")
}

/// Builds the Intel PCS request for a platform-data secret, validating the secret name (the
/// node's QE ID) and every field that is forwarded to Intel PCS.
pub fn prepare_registration(
    secret_name: &str,
    data: &BTreeMap<String, ByteString>,
) -> Result<PckCertsRequest> {
    ensure!(
        is_fixed_len_hex::<QE_ID_HEX_LEN>(secret_name),
        "Invalid platform-data secret name: expected a {QE_ID_HEX_LEN}-character hex QE ID"
    );

    let request = PckCertsRequest::from_secret_data(data)?;

    ensure!(
        is_fixed_len_hex::<CPU_SVN_HEX_LEN>(&request.cpu_svn),
        "Invalid cpu_svn: expected a {CPU_SVN_HEX_LEN}-character hex string, got {} bytes",
        request.cpu_svn.len()
    );
    ensure!(
        is_fixed_len_hex::<PCE_ID_HEX_LEN>(&request.pce_id),
        "Invalid pce_id: expected a {PCE_ID_HEX_LEN}-character hex string, got {} bytes",
        request.pce_id.len()
    );

    let manifest = &request.platform_manifest;
    ensure!(
        !manifest.is_empty()
            && manifest.len() <= PLATFORM_MANIFEST_MAX_HEX_LEN
            && manifest.len() % 2 == 0
            && manifest.bytes().all(|b| b.is_ascii_hexdigit()),
        "Invalid platform_manifest: expected a non-empty, even-length hex string of at most \
         {PLATFORM_MANIFEST_MAX_HEX_LEN} characters, got {} bytes",
        manifest.len()
    );

    Ok(request)
}

#[cfg(test)]
mod tests {
    use super::*;

    const QE_ID: &str = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4";

    fn valid_data() -> BTreeMap<String, ByteString> {
        [
            ("platform_manifest", "0011aabb".to_string()),
            ("pce_id", "0000".to_string()),
            ("cpu_svn", "0102030405060708090a0b0c0d0e0f10".to_string()),
            ("pce_svn", "0b00".to_string()),
            ("qe_id", QE_ID.to_string()),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), ByteString(v.into_bytes())))
        .collect()
    }

    fn with_field(field: &str, value: &[u8]) -> BTreeMap<String, ByteString> {
        let mut data = valid_data();
        data.insert(field.to_string(), ByteString(value.to_vec()));
        data
    }

    #[test]
    fn accepts_valid_platform_data() {
        let request = prepare_registration(QE_ID, &valid_data()).expect("should be valid");
        assert_eq!(request.platform_manifest, "0011aabb");
        assert_eq!(request.pce_id, "0000");
        assert_eq!(request.cpu_svn, "0102030405060708090a0b0c0d0e0f10");
    }

    #[test]
    fn rejects_invalid_secret_name() {
        for name in [
            "",
            "a1b2",
            "some-node-name",
            "../../a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
        ] {
            assert!(
                prepare_registration(name, &valid_data()).is_err(),
                "{name:?} should be rejected"
            );
        }
    }

    #[test]
    fn rejects_missing_fields() {
        for field in ["platform_manifest", "pce_id", "cpu_svn"] {
            let mut data = valid_data();
            data.remove(field);
            assert!(
                prepare_registration(QE_ID, &data).is_err(),
                "missing {field} should be rejected"
            );
        }
    }

    #[test]
    fn rejects_malformed_fields() {
        let too_long_manifest = "00".repeat(u16::MAX as usize + 1);
        let cases: [(&str, &[u8]); 9] = [
            ("cpu_svn", b"0102"),
            ("cpu_svn", b"0102030405060708090a0b0c0d0e0fzz"),
            ("pce_id", b"00000"),
            ("pce_id", b"00\xff\xfe"),
            ("platform_manifest", b""),
            ("platform_manifest", b"abc"),
            ("platform_manifest", b"00\"},{\"x\":\""),
            ("platform_manifest", b"0g"),
            ("platform_manifest", too_long_manifest.as_bytes()),
        ];
        for (field, value) in cases {
            assert!(
                prepare_registration(QE_ID, &with_field(field, value)).is_err(),
                "{field}={:?} should be rejected",
                String::from_utf8_lossy(&value[..value.len().min(32)])
            );
        }
    }

    #[test]
    fn accepts_maximum_size_manifest() {
        let manifest = "ab".repeat(u16::MAX as usize);
        let data = with_field("platform_manifest", manifest.as_bytes());
        assert!(prepare_registration(QE_ID, &data).is_ok());
    }

    #[test]
    fn fingerprint_is_stable_and_input_sensitive() {
        let request = prepare_registration(QE_ID, &valid_data()).unwrap();
        let fingerprint = registration_fingerprint(&request);
        assert!(fingerprint.starts_with("sha256:"));
        assert_eq!(fingerprint.len(), "sha256:".len() + 64);
        assert_eq!(fingerprint, registration_fingerprint(&request));

        // Fields not sent to PCS don't affect the fingerprint
        let other = prepare_registration(QE_ID, &with_field("pce_svn", b"0c00")).unwrap();
        assert_eq!(fingerprint, registration_fingerprint(&other));

        for (field, value) in [
            ("platform_manifest", "0011aabc"),
            ("pce_id", "0001"),
            ("cpu_svn", "0102030405060708090a0b0c0d0e0f11"),
        ] {
            let changed =
                prepare_registration(QE_ID, &with_field(field, value.as_bytes())).unwrap();
            assert_ne!(
                fingerprint,
                registration_fingerprint(&changed),
                "{field} change should change the fingerprint"
            );
        }
    }

    #[test]
    fn fingerprint_field_boundaries_are_unambiguous() {
        let a = PckCertsRequest {
            platform_manifest: "00".to_string(),
            pce_id: "1111".to_string(),
            cpu_svn: "22".to_string(),
        };
        let b = PckCertsRequest {
            platform_manifest: "0011".to_string(),
            pce_id: "11".to_string(),
            cpu_svn: "22".to_string(),
        };
        assert_ne!(registration_fingerprint(&a), registration_fingerprint(&b));
    }
}
