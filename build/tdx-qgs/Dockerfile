# Copyright (c) 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

# Named early so gpl-sources can read its dpkg database for exact versions.
FROM gcr.io/distroless/cc-debian13@sha256:4594d59540d1948417f6ca2829ddd9294493a7c68b7528f4dd459de7f203a750 AS final-base

# Bundle source for the LGPL shared libs above (gcc-14, glibc).
FROM rust:1.98.1-slim-trixie@sha256:3999a7ff854f315cf5f2b9a58071cb71196fdfc2ccd32fa20eedce8e754fd62a AS gpl-sources
WORKDIR /gpl-sources
# Derive package=version from the pinned base image's own dpkg database
# instead of hardcoding, so it never drifts from the pinned digest.
# gcc-14-base covers libgcc-s1/libgomp1/libstdc++6 too (same source: gcc-14).
COPY --from=final-base /var/lib/dpkg/status.d/libc6 \
                  /var/lib/dpkg/status.d/gcc-14-base \
                  /dpkg-status/
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl jq \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /dpkg-admin \
    && for f in /dpkg-status/*; do printf 'Status: install ok installed\n'; cat "$f"; echo; done \
         > /dpkg-admin/status \
    && PKGS=$(dpkg-query --admindir=/dpkg-admin -f '${source:Package}=${source:Version}\n' \
         -W $(ls /dpkg-status) | sort -u) \
    && for pv in $PKGS; do \
         pkg=${pv%=*}; ver=${pv#*=}; \
         echo "Fetching LGPL source for: $pv"; \
         curl -sSLf "https://snapshot.debian.org/mr/package/$pkg/$ver/srcfiles?fileinfo=1" \
           | jq -r '.fileinfo | to_entries[] | .key as $hash | .value[0].name as $name | "\($hash) \($name)"' \
           | while read -r hash name; do \
               curl -sSLf "https://snapshot.debian.org/file/$hash" -o "$name"; \
             done; \
       done

FROM rust:1.98.1-slim-trixie@sha256:3999a7ff854f315cf5f2b9a58071cb71196fdfc2ccd32fa20eedce8e754fd62a AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    make \
    ca-certificates \
    gnupg \
    && rm -rf /var/lib/apt/lists/*

# cargo-about generates a third-party license/copyright notices report for the
# Rust dependency tree. Installed early so this layer is cached independent of
# source code changes.
RUN cargo install cargo-about --locked --features cli

ARG DCAP_TARBALL_SHA256="977d652e6efa2fcb6ec7763db08ae5bbb6be8948c3aec55642832b5a940e9a74"

# Download and install Intel SGX local repository
RUN curl -fsSL https://download.01.org/intel-sgx/sgx-dcap/1.27/linux/distro/Debian13/sgx_debian_local_repo.tgz -o sgx_debian_local_repo.tgz \
    && echo "$DCAP_TARBALL_SHA256 sgx_debian_local_repo.tgz" | sha256sum -c - \
    && tar xzf sgx_debian_local_repo.tgz \
    && mkdir -p /etc/apt/keyrings \
    && gpg --dearmor < /sgx_debian_local_repo/keys/intel-sgx.key \
         > /etc/apt/keyrings/intel-sgx.gpg \
    && echo "deb [signed-by=/etc/apt/keyrings/intel-sgx.gpg arch=amd64] file:/sgx_debian_local_repo trixie main" > /etc/apt/sources.list.d/intel-sgx.list

# Install SGX development packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    libsgx-headers \
    libsgx-urts \
    && rm -rf /var/lib/apt/lists/*

# Copy source code
WORKDIR /build
COPY Cargo.toml Cargo.lock about.toml about.hbs ./

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

# Generate third-party license/copyright notices for pck-cert-tool's dependency tree
RUN mkdir -p /rootfs/usr/local/share/pck-cert-tool \
    && cargo about generate about.hbs \
         --target x86_64-unknown-linux-gnu \
         -o /rootfs/usr/local/share/pck-cert-tool/THIRD-PARTY-LICENSES.html \
         --manifest-path bin/pck-cert-tool/Cargo.toml

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
    && echo '{"local_cache_only": true}' > /rootfs/opt/intel/tdx-qgs/qcnl.conf \
    && grep -Fxvf /tmp/base-pkglist.txt /tmp/final-pkglist.txt \
         > /rootfs/usr/local/share/pck-cert-tool/added-packages.txt \
    && rm /tmp/base-pkglist.txt /tmp/final-pkglist.txt \
    && cp /build/bin/get-platform-info/get_platform_info /rootfs/usr/local/bin/ \
    && cp /build/target/release/pck-cert-tool /rootfs/usr/local/bin/

COPY LICENSE /rootfs/usr/local/share/pck-cert-tool/LICENSE
COPY --from=gpl-sources /gpl-sources /rootfs/usr/local/share/pck-cert-tool/gpl-sources

# Final stage — distroless/cc-debian13 provides glibc, libgcc, libstdc++, libssl, ca-certificates
FROM final-base
COPY --from=builder /rootfs/ /

# QCNL local caching is the only supported mode: this image ships without curl/libcurl,
# so the QCNL library can never reach out to a remote PCCS.
ENV QCNL_CONF_PATH=/opt/intel/tdx-qgs/qcnl.conf

# Run as nobody (uid 65534); distroless has no named users so use numeric UID
USER 65534:65534

ENTRYPOINT ["/opt/intel/tdx-qgs/qgs", "--no-daemon"]
