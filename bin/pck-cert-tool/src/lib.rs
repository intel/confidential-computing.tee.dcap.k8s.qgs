// Copyright(c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

//! Library half of `pck-cert-tool`: the Kubernetes/network-independent parsing, validation and
//! encoding logic, exposed so it can be unit tested and fuzzed in isolation.

pub mod cache;
pub mod pcs_client;
pub mod platform_data;
