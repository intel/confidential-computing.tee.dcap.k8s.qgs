# Copyright (c) 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

FROM registry.access.redhat.com/ubi10/ubi:latest@sha256:bc5a42833e4c84dbf7a29bcd4a0be414addad69e16210c2f0eb73986b356793c AS builder

# gcc is needed by the ring crate (C assembly)
RUN dnf install -y \
    gcc \
    curl \
    && dnf clean all

ARG RUST_VERSION="1.98.0"
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain ${RUST_VERSION}
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
FROM registry.access.redhat.com/ubi10/ubi-micro:latest@sha256:37fadb004c6bea628fcdd81376c8fb77bd8d9fd432d90503af4d9e76b1ff7191

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
