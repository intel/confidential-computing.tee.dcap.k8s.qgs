# Copyright (c) 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

FROM rust:1.99.0-slim-trixie@sha256:2752b332db73fdbb7dc576f06c82ed1f312005784ef913d7e04a28f5f55dc581 AS builder

# Install musl target for static linking
RUN rustup target add x86_64-unknown-linux-musl

# Install musl-tools for static linking
RUN apt-get update && apt-get install -y --no-install-recommends \
    musl-tools \
    && rm -rf /var/lib/apt/lists/*

# cargo-about generates a third-party license/copyright notices report for the
# Rust dependency tree. Installed early so this layer is cached independent of
# source code changes.
RUN cargo install cargo-about --locked --features cli

WORKDIR /build

# Copy workspace manifest and lock file first for better layer caching
COPY Cargo.toml Cargo.lock about.toml about.hbs ./

# Copy member Cargo.tomls and sources for workspace resolution
COPY bin/operator/Cargo.toml bin/operator/Cargo.toml
COPY bin/operator/src bin/operator/src
COPY bin/operator/templates bin/operator/templates
COPY bin/pck-cert-tool/Cargo.toml bin/pck-cert-tool/Cargo.toml
COPY bin/pck-cert-tool/src bin/pck-cert-tool/src

# Build the operator binary using musl for a static binary
RUN cargo build --release --target x86_64-unknown-linux-musl -p operator

# Generate third-party license/copyright notices for operator's dependency tree
RUN mkdir -p /rootfs/usr/local/share/operator \
    && cargo about generate about.hbs \
         --target x86_64-unknown-linux-musl \
         -o /rootfs/usr/local/share/operator/THIRD-PARTY-LICENSES.html \
         --manifest-path bin/operator/Cargo.toml

# Final stage - use distroless
FROM gcr.io/distroless/static-debian13:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3

# Copy the static binary from builder
COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/operator /operator
COPY --from=builder /rootfs/usr/local/share/operator/THIRD-PARTY-LICENSES.html /usr/local/share/operator/THIRD-PARTY-LICENSES.html
COPY LICENSE /usr/local/share/operator/LICENSE

# Use nobody (uid=65534)
USER 65534:65534

ENTRYPOINT ["/operator"]
