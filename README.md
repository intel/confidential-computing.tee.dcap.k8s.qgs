# Intel® TDX Quote Generation and Collateral Services for Kubernetes

[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/intel/confidential-computing.tee.dcap.k8s.qgs/badge)](https://scorecard.dev/viewer/?uri=github.com/intel/confidential-computing.tee.dcap.k8s.qgs)
[![Rust CI](https://github.com/intel/confidential-computing.tee.dcap.k8s.qgs/actions/workflows/ci-rust.yaml/badge.svg?branch=main)](https://github.com/intel/confidential-computing.tee.dcap.k8s.qgs/actions/workflows/ci-rust.yaml)
[![e2e tests](https://github.com/intel/confidential-computing.tee.dcap.k8s.qgs/actions/workflows/ci-e2e.yaml/badge.svg?branch=main)](https://github.com/intel/confidential-computing.tee.dcap.k8s.qgs/actions/workflows/ci-e2e.yaml)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

Tools and a Kubernetes operator for running Intel® Trust Domain Extensions (TDX) Quote Generation Service (QGS) and provisioning the PCK certificates it needs for remote attestation.

## Overview

This repository automates the distribution of platform-specific PCK (Provisioning Certification Key) certificates to TDX-capable worker nodes, so QGS pods can generate attestation quotes locally without depending on the Intel Provisioning Certification Service (PCS) at runtime. Certificates can be provisioned online (PCS-connected), offline (air-gapped), or by an external system.

This follows the [Indirect Registration](https://cc-enabling.trustedservices.intel.com/intel-tdx-enabling-guide/02/infrastructure_setup/#indirect-registration) model: each platform's manifest is sent to Intel PCS with every registration request rather than registered once upfront. Because each node's PCK certificate is written straight into its local on-disk QPL cache, no separate caching service (e.g., PCCS) is needed.

![Architecture Diagram](architecture.svg)

## How It Works

1. **①** The QGS Pod's `Init: Get Platform Info` container (`pck-cert-tool get-platforms`) collects platform data (CPU SVN, PCE ID, PCE SVN, QE ID, platform manifest) and creates a Platform Data Secret (`type=platform-data`).
2. **②** The PCK Cert Registrar Pod (`pck-cert-tool register`) watches for new Platform Data Secrets.
3. **③④** The Registrar exchanges the platform data with Intel PCS (`/pckcerts/config`, `/tcb`) for matching PCK certificates and TCB info (Online mode only).
4. **⑤⑥⑦** The Registrar writes a PCK Cert Secret (`fmspc=...`); the QGS Pod's `Init: Watch Certificates` container watches and mounts it into the node's local QPL cache, so the `Main: TDX QGS` container can generate attestation quotes without fetching its own PCK certificate from Intel PCS at request time.

See [QUICKSTART.md](QUICKSTART.md) to deploy end-to-end.

## Components

- [pck-cert-tool](bin/pck-cert-tool/README.md) — CLI for collecting platform data and provisioning PCK certificates
- [intel-tdx-dcap-operator](bin/operator/README.md) — Kubernetes operator managing the QGS lifecycle via the `TdxQuoteGenerationService` CRD
- [Container images](DOCKER.md) — build and deployment guide

## License

Licensed under the [Apache License, Version 2.0](LICENSE).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).
