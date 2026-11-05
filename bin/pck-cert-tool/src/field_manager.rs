// Copyright(c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

/// Stable server-side apply field manager for Secrets written by this tool.
const FIELD_MANAGER: &str = "pck-cert-tool";

pub fn field_manager() -> &'static str {
    FIELD_MANAGER
}

pub fn scoped_field_manager(scope: &str) -> String {
    format!("{FIELD_MANAGER}/{scope}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_stable_field_manager_names() {
        assert_eq!(field_manager(), "pck-cert-tool");
        assert_eq!(
            scoped_field_manager("platform-id"),
            "pck-cert-tool/platform-id"
        );
    }
}
