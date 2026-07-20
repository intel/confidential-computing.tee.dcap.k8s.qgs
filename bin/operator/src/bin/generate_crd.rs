// Copyright(c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

//! Regenerate the CRD YAML from the Rust type definitions.
//!
//! Usage:
//!   cargo run --bin generate_crd > deployment/crd/tdxquotegenerationservice-crd.yaml

use kube::CustomResourceExt;
use operator::tdx_quote_generation_service::TdxQuoteGenerationService;

fn main() {
    let crd = TdxQuoteGenerationService::crd();
    print!(
        "{}",
        serde_yaml::to_string(&crd).expect("failed to serialize CRD")
    );
}
