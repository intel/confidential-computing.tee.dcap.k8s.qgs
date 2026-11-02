// Copyright(c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

//! operator - A Kubernetes operator built with kube-rs

use kube::Client;
use operator::tdx_quote_generation_service::controller;
use tracing::info;

mod error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    info!("Starting operator");

    let client = Client::try_default().await?;

    // Runs until SIGTERM or Ctrl-C, letting in-flight reconciles finish
    controller::run(client).await?;

    info!("Operator shut down");
    Ok(())
}
