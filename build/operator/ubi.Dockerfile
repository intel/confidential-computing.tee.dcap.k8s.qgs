# Copyright (c) 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

FROM registry.access.redhat.com/ubi10/ubi:latest@sha256:27e14f4987d7abe56664d7e1b1dddcd0226d4ca593da5726f0f65697a17d0fee AS builder

# gcc is needed by the ring crate (C assembly)
RUN dnf install -y \
    gcc \
    curl \
    rust-toolset \
    && dnf clean all

# cargo-about generates a third-party license/copyright notices report for the
# Rust dependency tree. Installed early so this layer is cached independent of
# source code changes.
RUN cargo install cargo-about --locked --features cli

WORKDIR /build

COPY Cargo.toml Cargo.lock about.toml about.hbs ./
COPY bin/operator/Cargo.toml bin/operator/Cargo.toml
COPY bin/operator/src bin/operator/src
COPY bin/operator/templates bin/operator/templates
COPY bin/pck-cert-tool/Cargo.toml bin/pck-cert-tool/Cargo.toml
COPY bin/pck-cert-tool/src bin/pck-cert-tool/src

RUN cargo build --release -p operator

# Generate third-party license/copyright notices for operator's dependency tree
RUN mkdir -p /rootfs/licenses \
    && cargo about generate about.hbs \
         --target x86_64-unknown-linux-gnu \
         -o /rootfs/licenses/THIRD-PARTY-LICENSES.html \
         --manifest-path bin/operator/Cargo.toml

# Final stage — ubi-micro; operator uses rustls/ring so only needs glibc
FROM registry.access.redhat.com/ubi10/ubi-micro:latest@sha256:5b13e670e107509be71c066180032017ff5dddff2b6cd60d16311a5cea309953

COPY --from=builder /build/target/release/operator /operator
COPY --from=builder /rootfs/licenses/THIRD-PARTY-LICENSES.html /licenses/THIRD-PARTY-LICENSES.html
COPY LICENSE /licenses/LICENSE

# Run as nobody (uid 65534)
USER 65534:65534

ENTRYPOINT ["/operator"]

LABEL vendor='Intel®'
LABEL org.opencontainers.image.source='https://github.com/intel/confidential-computing.tee.dcap.k8s.qgs'
LABEL maintainer="Intel®"
LABEL version='devel'
LABEL release='1'
LABEL name='intel-tdx-dcap-operator'
LABEL summary='Intel® TDX DCAP operator for Kubernetes'
LABEL description='Zero-touch Intel® TDX DCAP platform registration and QGS deployment in OpenShift, enabling confidential computing workloads to generate remote attestation quotes.'
