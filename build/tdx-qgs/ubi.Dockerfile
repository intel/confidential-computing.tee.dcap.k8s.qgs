# Copyright (c) 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

# Multi-stage Dockerfile for pck-cert-tool and get-platform-info
# Based on registry.access.redhat.com/ubi10/ubi
FROM registry.access.redhat.com/ubi10/ubi:latest@sha256:bc5a42833e4c84dbf7a29bcd4a0be414addad69e16210c2f0eb73986b356793c AS builder

ARG DCAP_TARBALL_SHA256="8819eeb865245a816c0ed335ad3a289ce1024f032af1ed29fe5ec216f3305266"

RUN dnf install -y \
    gcc \
    make \
    ca-certificates \
    curl \
    boost-thread \
    && dnf clean all

# Download and install Intel SGX DCAP local RPM repository
RUN curl -fsSL https://download.01.org/intel-sgx/sgx-dcap/1.27/linux/distro/rhel10.2-server/sgx_rpm_local_repo.tgz \
        -o /tmp/sgx_rpm_local_repo.tgz \
    && echo "$DCAP_TARBALL_SHA256 /tmp/sgx_rpm_local_repo.tgz" | sha256sum -c - \
    && tar -xzf /tmp/sgx_rpm_local_repo.tgz -C /tmp \
    && rm /tmp/sgx_rpm_local_repo.tgz \
    && dnf config-manager --add-repo file:///tmp/sgx_rpm_local_repo \
    && dnf config-manager --save \
        --setopt="tmp_sgx_rpm_local_repo.name=Intel SGX Local Repo" \
        --setopt=tmp_sgx_rpm_local_repo.gpgcheck=1 \
        --setopt=tmp_sgx_rpm_local_repo.repo_gpgcheck=1 \
        --setopt=tmp_sgx_rpm_local_repo.gpgkey=file:///tmp/sgx_rpm_local_repo/keys/intel-sgx.key \
        --setopt=tmp_sgx_rpm_local_repo.priority=1

# Install Intel's split SGX packages and QGS.
RUN dnf install -y \
    libsgx-headers \
    libsgx-urts \
    libsgx-enclave-common \
    libsgx-ae-pce \
    libsgx-ae-id-enclave \
    libsgx-ae-tdqe \
    libsgx-pce-logic \
    libsgx-qe3-logic \
    libsgx-tdx-logic \
    libsgx-dcap-ql \
    libsgx-dcap-default-qpl \
    tdx-qgs \
    && dnf clean all

# Install Rust
ARG RUST_VERSION="1.98.0"
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain ${RUST_VERSION}
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
        App_Include_Paths=-I/usr/include \
        App_Link_Flags="-pie -lsgx_urts -lpthread -Wl,-z,relro,-z,now -Wl,-z,nodlopen -Wl,-z,noexecstack -L/usr/lib64 -Wl,-rpath,/usr/lib64" \
        ID_ENCLAVE_PATH=/usr/lib64/libsgx_id_enclave.signed.so.1 \
        PCE_ENCLAVE_PATH=/usr/lib64/libsgx_pce.signed.so.1 \
    && chmod +x bin/get-platform-info/get_platform_info

RUN cargo build --release -p pck-cert-tool \
    && chmod +x target/release/pck-cert-tool

# Assemble /rootfs for the final stage
RUN lib=/usr/lib64 \
    && mkdir -p /rootfs${lib} /rootfs/opt/intel /rootfs/etc \
               /rootfs/usr/local/bin /rootfs/usr/local/share/pck-cert-tool \
               /rootfs/var/opt/qgsd /rootfs/licenses \
    && cp -a ${lib}/libsgx_enclave_common.so.* \
             ${lib}/libsgx_urts.so.* \
             ${lib}/libsgx_id_enclave.signed.so.* \
             ${lib}/libsgx_pce.signed.so.* \
             ${lib}/libsgx_pce_logic.so.* \
             ${lib}/libsgx_qe3_logic.so* \
             ${lib}/libsgx_qe3.signed.so.* \
             ${lib}/libsgx_tdqe.signed.so.* \
             ${lib}/libsgx_tdx_logic.so.* \
             ${lib}/libsgx_dcap_ql.so.* \
             ${lib}/libdcap_quoteprov.so.* \
             ${lib}/libsgx_default_qcnl_wrapper.so.* \
             ${lib}/libboost_system.so.* \
             ${lib}/libboost_thread.so.* \
             /rootfs${lib}/ \
    && cp -a /opt/intel/tdx-qgs /rootfs/opt/intel/ \
    && cp /etc/qgs.conf /rootfs/etc/ \
    && rpm -qa --queryformat '%{NAME}\n' \
         > /rootfs/usr/local/share/pck-cert-tool/added-packages.txt \
    && cp /build/bin/get-platform-info/get_platform_info /rootfs/usr/local/bin/ \
    && cp /build/target/release/pck-cert-tool /rootfs/usr/local/bin/

COPY LICENSE /rootfs/licenses/LICENSE

# Final stage — ubi-minimal provides glibc, libstdc++, libgcc
FROM registry.access.redhat.com/ubi10/ubi-minimal:latest@sha256:d28951a21182cbc821da281af307a4d583dbc39d464680adc6fdffbc5a935b20

COPY --from=builder /rootfs/ /

# Run as nobody
USER nobody

ENTRYPOINT ["/opt/intel/tdx-qgs/qgs", "--no-daemon"]

LABEL vendor='Intel®'
LABEL org.opencontainers.image.source='https://github.com/intel/confidential-computing.tee.dcap.k8s.qgs'
LABEL maintainer="Intel®"
LABEL version='devel'
LABEL release='1'
LABEL name='intel-tdx-dcap-operator'
LABEL summary='Intel® TDX DCAP operator for Kubernetes'
LABEL description='Zero-touch Intel® TDX DCAP platform registration and QGS deployment in OpenShift, enabling confidential computing workloads to generate remote attestation quotes.'
