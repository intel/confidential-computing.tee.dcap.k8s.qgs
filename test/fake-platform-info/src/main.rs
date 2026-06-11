// Fake platform info binary for e2e testing without SGX hardware.
//
// Produces a deterministic qe_id by taking the first 16 bytes of the SHA-256
// hash of NODE_NAME (injected via the Downward API fieldRef spec.nodeName),
// formatted as 32 lowercase hex chars.  On real hardware the qe_id is derived
// from the physical platform; using the node name mirrors that semantics —
// one stable identity per node — and survives pod restarts.
//
// Field lengths required by pck-cert-tool:
//   cpu_svn  32 ASCII hex chars
//   pce_id    4 ASCII hex chars
//   pce_svn   4 ASCII hex chars
//   qe_id    32 ASCII hex chars
// enc_ppid is present (matches binary contract) but ignored by pck-cert-tool.
use sha2::{Digest, Sha256};

fn main() {
    let node_name =
        std::env::var("NODE_NAME").expect("NODE_NAME env var must be set (Downward API)");

    println!(
        r#"{{"cpu_svn":"0102030405060708090a0b0c0d0e0f10","enc_ppid":"{}","pce_id":"0000","pce_svn":"0b00","qe_id":"{}"}}"#,
        "ab".repeat(384),
        hex::encode(&Sha256::digest(node_name.as_bytes())[..16]),
    );
}
