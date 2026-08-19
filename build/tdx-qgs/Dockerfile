# Copyright (c) 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

FROM debian:13@sha256:3352c2e13876c8a5c5873ef20870e1939e73cb9a3c1aeba5e3e72172a85ce9ed AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    build-essential \
    pkg-config \
    libssl-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ARG DCAP_TARBALL_SHA256="977d652e6efa2fcb6ec7763db08ae5bbb6be8948c3aec55642832b5a940e9a74"

# Download and install Intel SGX local repository
RUN curl -fsSL https://download.01.org/intel-sgx/sgx-dcap/1.27/linux/distro/Debian13/sgx_debian_local_repo.tgz -o sgx_debian_local_repo.tgz \
    && echo "$DCAP_TARBALL_SHA256 sgx_debian_local_repo.tgz" | sha256sum -c - \
    && tar xzf sgx_debian_local_repo.tgz \
    && echo "deb [trusted=yes arch=amd64] file:/sgx_debian_local_repo trixie main" > /etc/apt/sources.list.d/intel-sgx.list

# Install SGX development packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    libsgx-headers \
    libsgx-urts \
    && rm -rf /var/lib/apt/lists/*

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Copy source code
WORKDIR /build
COPY Cargo.toml Cargo.lock ./

# Copy member Cargo.tomls and sources for workspace resolution
COPY bin/operator/Cargo.toml bin/operator/Cargo.toml
COPY bin/operator/src bin/operator/src
COPY bin/pck-cert-tool/Cargo.toml bin/pck-cert-tool/Cargo.toml
COPY bin/pck-cert-tool/src bin/pck-cert-tool/src

# Build get-platform-info
COPY bin/get-platform-info bin/get-platform-info
RUN make -C bin/get-platform-info clean && make -C bin/get-platform-info \
    && chmod +x bin/get-platform-info/get_platform_info

# Build pck-cert-tool
RUN cargo build --release -p pck-cert-tool \
    && chmod +x target/release/pck-cert-tool

RUN dpkg-query -W -f='${Package}\n' > /tmp/base-pkglist.txt \
    && apt-get update && apt-get install -y --no-install-recommends \
        libsgx-ae-id-enclave \
        libsgx-ae-pce \
        tdx-qgs \
        libsgx-dcap-ql \
        libsgx-dcap-default-qpl \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /sgx_debian_local_repo /etc/apt/sources.list.d/intel-sgx.list \
    && dpkg-query -W -f='${Package}\n' > /tmp/final-pkglist.txt \
    && lib=/usr/lib/x86_64-linux-gnu \
    && mkdir -p /rootfs${lib} /rootfs/opt/intel \
               /rootfs/usr/local/bin /rootfs/usr/local/share/pck-cert-tool \
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
             ${lib}/libboost_thread.so.* \
             /rootfs${lib}/ \
    && cp -a /opt/intel/tdx-qgs /rootfs/opt/intel/ \
    && grep -Fxvf /tmp/base-pkglist.txt /tmp/final-pkglist.txt \
         > /rootfs/usr/local/share/pck-cert-tool/added-packages.txt \
    && rm /tmp/base-pkglist.txt /tmp/final-pkglist.txt \
    && cp /build/bin/get-platform-info/get_platform_info /rootfs/usr/local/bin/ \
    && cp /build/target/release/pck-cert-tool /rootfs/usr/local/bin/

COPY LICENSE /rootfs/usr/local/share/pck-cert-tool/LICENSE

# Final stage — distroless/cc-debian13 provides glibc, libgcc, libstdc++, libssl, ca-certificates
FROM gcr.io/distroless/cc-debian13@sha256:ed7c407fd64eb0af9dddb9456b94cee188a40a7f53cf38c9836e1e9ae14fca02

COPY --from=builder /rootfs/ /

# Run as nobody (uid 65534); distroless has no named users so use numeric UID
USER 65534:65534

ENTRYPOINT ["/opt/intel/tdx-qgs/qgs", "--no-daemon"]
