# Copyright (c) 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

FROM registry.access.redhat.com/ubi10/ubi:latest@sha256:9d3b5102e7ae4f82914a1791610b75acef134b93158be6005b6ae9218c163550 AS builder

# gcc is needed by the ring crate (C assembly)
RUN dnf install -y \
    gcc \
    curl \
    && dnf clean all

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /build

COPY Cargo.toml Cargo.lock ./
COPY bin/operator/Cargo.toml bin/operator/Cargo.toml
COPY bin/operator/src bin/operator/src
COPY bin/operator/templates bin/operator/templates
COPY bin/pck-cert-tool/Cargo.toml bin/pck-cert-tool/Cargo.toml
COPY bin/pck-cert-tool/src bin/pck-cert-tool/src

RUN cargo build --release -p operator

# Final stage — ubi-micro; operator uses rustls/ring so only needs glibc
FROM registry.access.redhat.com/ubi10/ubi-micro:latest@sha256:6b19fae23a4bab50b2494471674577365a64667365d658671e3f9e8a5a698df3

COPY --from=builder /build/target/release/operator /operator
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
