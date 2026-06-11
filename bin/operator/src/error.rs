// Copyright(c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

//! Error types for operator

use thiserror::Error;

/// Main error type for the operator
#[derive(Error, Debug)]
pub enum Error {
    /// Kubernetes API error
    #[error("Kubernetes API error: {0}")]
    Kube(#[from] kube::Error),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Finalizer error during reconciliation
    #[error("Finalizer error: {0}")]
    #[allow(dead_code)] // Used in controller.rs line 73, false positive from thiserror derive
    Finalizer(Box<dyn std::error::Error + Send + Sync>),

    /// Generic error
    #[error("{0}")]
    #[allow(dead_code)]
    // Used in controller.rs lines 297, 320, 331, false positive from thiserror derive
    Generic(String),
}

#[allow(dead_code)] // Used via `use crate::error::Result` in controller.rs:30 and finalizer.rs:12
pub type Result<T> = std::result::Result<T, Error>;
