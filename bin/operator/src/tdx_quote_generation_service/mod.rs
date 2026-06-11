// Copyright(c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

//! TdxQuoteGenerationService CRD module

pub mod controller;
pub mod finalizer;
pub mod status;
pub mod types;

pub use finalizer::FINALIZER;
pub use status::{Condition, ConditionManager, ConditionStatus};
pub use types::TdxQuoteGenerationServiceSpec;
pub use types::TdxQuoteGenerationServiceStatus;
pub use types::{PlatformRegistration, TdxQuoteGenerationService};
