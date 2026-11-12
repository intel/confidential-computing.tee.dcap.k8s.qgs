// Copyright(c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

//! Library half of `pck-cert-tool`: the Kubernetes/network-independent parsing, validation and
//! encoding logic, exposed so it can be unit tested and fuzzed in isolation.

pub mod cache;
pub mod pck_secret;
pub mod pcs_client;
pub mod platform_data;

/// Server-side apply field manager for all Secrets written by this tool. Keep it stable:
/// changing it leaves the field ownership in existing Secrets with the old manager.
pub const FIELD_MANAGER: &str = "pck-cert-tool";
