// Copyright(c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

//! operator - A Kubernetes operator built with kube-rs

use kube::Client;
use tracing::{Level, info};
use tracing_subscriber::FmtSubscriber;

mod error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    info!("Starting operator");

    // Create Kubernetes client
    let client = Client::try_default().await?;

    info!("operator initialized successfully");

    // Start TdxQuoteGenerationService controller
    use operator::tdx_quote_generation_service::controller;

    let controller_task = tokio::spawn(controller::run(client.clone()));
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;

    tokio::select! {
        result = controller_task => {
            match result {
                Ok(Ok(())) => {
                    return Err(std::io::Error::other(
                        "TdxQuoteGenerationService controller exited unexpectedly",
                    ).into());
                }
                Ok(Err(err)) => return Err(err.into()),
                Err(err) => return Err(err.into()),
            }
        }
        signal = tokio::signal::ctrl_c() => {
            signal?;
            info!("Shutting down operator");
        }
        _ = sigterm.recv() => {
            info!("Received SIGTERM, shutting down operator");
        }
    }

    Ok(())
}
