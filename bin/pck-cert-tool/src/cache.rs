// Copyright(c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Error};

const EXPIRE_HOURS: u64 = 8760; // 1 year

const SGX_QPL_CACHE_MULTICERTS: u16 = 1 << 2;

/// Build cache file format as per PCS client tool.
/// Cache format matches the PCS client cache layout.
/// Format: header(14 bytes) + tcbcomponent + tcbinfo + certchain + pckcerts.
pub fn build_cache_blob(
    cpu_svn: &str,
    tcb_info: &str,
    cert_chain: &str,
    filtered_pck_certs_json: &str,
) -> anyhow::Result<(Vec<u8>, u64)> {
    let expiration_time = get_expiration_time()?;

    let mut cache_data = Vec::new();

    // Write cache header: version(u16) + flags(u32) + expiration(u64) in little-endian
    cache_data.extend_from_slice(&1u16.to_le_bytes());
    cache_data.extend_from_slice(&(SGX_QPL_CACHE_MULTICERTS as u32).to_le_bytes());
    cache_data.extend_from_slice(&expiration_time.to_le_bytes());

    // Helper function to write length-prefixed data
    let write_field = |buf: &mut Vec<u8>, data: &str| -> anyhow::Result<()> {
        let bytes = data.as_bytes();
        let len: u32 = bytes
            .len()
            .try_into()
            .context("Cache field too large to encode")?;
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(bytes);
        Ok(())
    };

    // Write TCB component (CPU SVN from the platform)
    write_field(&mut cache_data, cpu_svn)?;

    // Write TCB info
    write_field(&mut cache_data, tcb_info)?;

    // Write certificate chain (keep URL-encoded)
    write_field(&mut cache_data, cert_chain)?;

    // Write PCK certificates JSON (filtered and verified)
    write_field(&mut cache_data, filtered_pck_certs_json)?;

    Ok((cache_data, expiration_time))
}

fn get_expiration_time() -> Result<u64, Error> {
    let expiration_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("System time error")?
        .as_secs()
        + (EXPIRE_HOURS * 60 * 60);
    Ok(expiration_time)
}

#[cfg(test)]
mod tests {
    use super::{build_cache_blob, EXPIRE_HOURS, SGX_QPL_CACHE_MULTICERTS};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn read_u16_le(data: &[u8], offset: &mut usize) -> u16 {
        let value = u16::from_le_bytes(data[*offset..*offset + 2].try_into().unwrap());
        *offset += 2;
        value
    }

    fn read_u32_le(data: &[u8], offset: &mut usize) -> u32 {
        let value = u32::from_le_bytes(data[*offset..*offset + 4].try_into().unwrap());
        *offset += 4;
        value
    }

    fn read_u64_le(data: &[u8], offset: &mut usize) -> u64 {
        let value = u64::from_le_bytes(data[*offset..*offset + 8].try_into().unwrap());
        *offset += 8;
        value
    }

    fn read_len_prefixed_str<'a>(data: &'a [u8], offset: &mut usize) -> &'a str {
        let len = read_u32_le(data, offset) as usize;
        let value = std::str::from_utf8(&data[*offset..*offset + len]).unwrap();
        *offset += len;
        value
    }

    #[test]
    fn build_cache_blob_encodes_expected_header_and_fields() {
        let cpu_svn = "0102030405060708090a0b0c0d0e0f10";
        let tcb_info = "{\"id\":\"TDX\",\"version\":3}";
        let cert_chain = "-----BEGIN%20CERTIFICATE-----";
        let pck_json = "[{\"tcbm\":\"abc\"}]";

        let before_now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let (blob, expiration_time) =
            build_cache_blob(cpu_svn, tcb_info, cert_chain, pck_json).unwrap();

        let expected_expiration_min = before_now + (EXPIRE_HOURS * 60 * 60);
        assert!(
            expiration_time >= expected_expiration_min,
            "expiration time should be at least one year from call start"
        );

        let mut offset = 0usize;
        assert_eq!(read_u16_le(&blob, &mut offset), 1);
        assert_eq!(read_u32_le(&blob, &mut offset), SGX_QPL_CACHE_MULTICERTS as u32);
        assert_eq!(read_u64_le(&blob, &mut offset), expiration_time);

        assert_eq!(read_len_prefixed_str(&blob, &mut offset), cpu_svn);
        assert_eq!(read_len_prefixed_str(&blob, &mut offset), tcb_info);
        assert_eq!(read_len_prefixed_str(&blob, &mut offset), cert_chain);
        assert_eq!(read_len_prefixed_str(&blob, &mut offset), pck_json);
        assert_eq!(offset, blob.len(), "blob should not contain trailing bytes");
    }
}
