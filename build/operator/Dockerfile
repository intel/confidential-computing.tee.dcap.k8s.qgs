# Copyright (c) 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

FROM rust:trixie AS builder

# Install musl target for static linking
RUN rustup target add x86_64-unknown-linux-musl

# Install musl-tools for static linking
RUN apt-get update && apt-get install -y --no-install-recommends \
    musl-tools \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy workspace manifest and lock file first for better layer caching
COPY Cargo.toml Cargo.lock ./

# Copy member Cargo.tomls and sources for workspace resolution
COPY bin/operator/Cargo.toml bin/operator/Cargo.toml
COPY bin/operator/src bin/operator/src
COPY bin/operator/templates bin/operator/templates
COPY bin/pck-cert-tool/Cargo.toml bin/pck-cert-tool/Cargo.toml
COPY bin/pck-cert-tool/src bin/pck-cert-tool/src

# Build the operator binary using musl for a static binary
RUN cargo build --release --target x86_64-unknown-linux-musl -p operator

# Final stage - use distroless
FROM gcr.io/distroless/static-debian13:nonroot

# Copy the static binary from builder
COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/operator /operator
COPY LICENSE /usr/local/share/operator/LICENSE

# Use nobody (uid=65534)
USER 65534:65534

ENTRYPOINT ["/operator"]
