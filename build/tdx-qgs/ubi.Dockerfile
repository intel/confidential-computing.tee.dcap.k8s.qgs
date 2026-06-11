# Copyright (c) 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

# Multi-stage Dockerfile for pck-cert-tool and get-platform-info
# Based on registry.access.redhat.com/ubi10/ubi
FROM registry.access.redhat.com/ubi10/ubi:latest AS builder

RUN dnf install -y \
    gcc \
    make \
    ca-certificates \
    curl \
    && dnf clean all

# Install Intel SGX SDK to get SGX headers and libraries for the build
ARG SGX_SDK_URL=https://download.01.org/intel-sgx/sgx-linux/2.28/distro/rhel10.0-server/sgx_linux_x64_sdk_2.28.100.1.bin
RUN curl -fsSL ${SGX_SDK_URL} -o /tmp/sgx_sdk.bin \
    && chmod +x /tmp/sgx_sdk.bin \
    && echo "yes" | /tmp/sgx_sdk.bin --prefix /opt/intel \
    && rm /tmp/sgx_sdk.bin

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY bin/operator/Cargo.toml bin/operator/Cargo.toml
COPY bin/operator/src bin/operator/src
COPY bin/pck-cert-tool/Cargo.toml bin/pck-cert-tool/Cargo.toml
COPY bin/pck-cert-tool/src bin/pck-cert-tool/src

COPY bin/get-platform-info bin/get-platform-info
RUN make -C bin/get-platform-info clean && \
    make -C bin/get-platform-info \
        App_Include_Paths=-I/opt/intel/sgxsdk/include \
        App_Link_Flags="-pie -lsgx_urts -lpthread -Wl,-z,relro,-z,now -Wl,-z,nodlopen -Wl,-z,noexecstack -L/opt/intel/sgxsdk/lib64 -Wl,-rpath,/opt/intel/sgxsdk/lib64" \
        ID_ENCLAVE_PATH=/usr/x86_64-intel-sgx/lib64/libsgx_id_enclave.signed.so.1 \
        PCE_ENCLAVE_PATH=/usr/x86_64-intel-sgx/lib64/libsgx_pce.signed.so.1 \
    && chmod +x bin/get-platform-info/get_platform_info

RUN cargo build --release -p pck-cert-tool \
    && chmod +x target/release/pck-cert-tool

# Final stage
FROM registry.access.redhat.com/ubi10/ubi-minimal:latest

RUN rpm -qa --queryformat '%{NAME}\n' > /tmp/base-pkglist.txt \
    && microdnf install -y --setopt=install_weak_deps=0 --nodocs \
        tdx-qgs \
        sgx-common \
    && microdnf clean all \
    && mkdir -p /usr/local/share/pck-cert-tool \
    && rpm -qa --queryformat '%{NAME}\n' > /tmp/final-pkglist.txt \
    && grep -Fxvf /tmp/base-pkglist.txt /tmp/final-pkglist.txt > /usr/local/share/pck-cert-tool/added-packages.txt \
    && rm /tmp/base-pkglist.txt /tmp/final-pkglist.txt

COPY --from=builder /build/bin/get-platform-info/get_platform_info /usr/local/bin/
COPY --from=builder /build/target/release/pck-cert-tool /usr/local/bin/
COPY build/tdx-qgs/qgs-wrapper.sh /usr/local/bin/qgs-wrapper.sh
COPY LICENSE /licenses/LICENSE

WORKDIR /work

# Default user is nobody; containers that require root (e.g. pck-certs-watcher,
# platform-registration) override this via runAsUser: 0 in the pod securityContext.
USER nobody

ENTRYPOINT ["/usr/local/bin/qgs-wrapper.sh"]

LABEL vendor='Intel®'
LABEL org.opencontainers.image.source='https://github.com/intel/confidential-computing.tee.dcap.k8s.qgs'
LABEL maintainer="Intel®"
LABEL version='devel'
LABEL release='1'
LABEL name='intel-tdx-dcap-operator'
LABEL summary='Intel® TDX DCAP operator for Kubernetes'
LABEL description='Zero-touch Intel® TDX DCAP platform registration and QGS deployment in OpenShift, enabling confidential computing workloads to generate remote attestation quotes.'
