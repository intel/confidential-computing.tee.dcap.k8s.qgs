# Docker Build Instructions

## Building the Images

Build from the repository root (required for Cargo workspace access):

```bash
# pck-cert-tool + get-platform-info + QGS
docker build -t intel-tdx-qgs:latest -f build/tdx-qgs/Dockerfile .

# operator
docker build -t intel-tdx-dcap-operator:latest -f build/operator/Dockerfile .
```

## What's Included

The Docker image contains:
- **pck-cert-tool**: Rust utility for managing PCK certificates and platform data
- **get_platform_info**: C utility for retrieving platform information
- Intel SGX and TDX runtime libraries:
  - libsgx-ae-id-enclave (ID enclave for platform identification)
  - libsgx-ae-pce (PCE enclave for platform certification)
  - libsgx-urts (SGX untrusted runtime)
  - tdx-qgs (TDX Quote Generation Service)
  - libsgx-dcap-ql (DCAP Quote Library)
  - libsgx-dcap-default-qpl (DCAP Quote Provider Library)

## Base Image

- Debian 12 (Bookworm)
- Multi-stage build to minimize final image size

## Usage Examples

### Check installed binaries

```bash
docker run --rm intel-tdx-qgs:latest pck-cert-tool --version
docker run --rm intel-tdx-qgs:latest get_platform_info
```

### Run get-platforms command

This requires access to EFI variables and SGX devices:

```bash
docker run --rm \
  --privileged \
  -v /sys/firmware/efi:/sys/firmware/efi:ro \
  -v /dev/sgx_enclave:/dev/sgx_enclave \
  -v /dev/sgx_provision:/dev/sgx_provision \
  -v ~/.kube:/root/.kube:ro \
  intel-tdx-qgs:latest \
  pck-cert-tool get-platforms -p /usr/local/bin/get_platform_info -n default
```

### Run get-certificates command

```bash
docker run --rm \
  -v /path/to/certs:/output \
  -v ~/.kube:/root/.kube:ro \
  intel-tdx-qgs:latest \
  pck-cert-tool get-certificates -p /usr/local/bin/get_platform_info -o /output -n default
```

## Using in Kubernetes

Deploy using the operator — see [bin/operator/README.md](bin/operator/README.md) for full instructions.

## Required Permissions

- **For get-platforms**: Requires privileged access to read EFI variables and access SGX devices
- **For get-certificates**: Requires Kubernetes API access (via kubeconfig or service account)
- **For register**: Requires Kubernetes API access and Intel PCS API key
- **SGX devices**: `/dev/sgx_enclave` and `/dev/sgx_provision` must be accessible via `sgx.intel.com/*` device plugin resoures.

NB: Cluster admins are expected to configure Pod Security Admission and Resource Quotas for all namespaces such that unwanted QGS hostPath volume access and/or `sgx.intel.com/*` resource use are blocked.

## Signed Container Images

The release images are signed with keyless signing using cosign. The signing proof is stored in [rekor.sigstore.dev](https://rekor.sigstore.dev) in an append-only transparency log.
The signature is stored in Docker Hub along with the images.

```bash
cosign verify --certificate-oidc-issuer https://token.actions.githubusercontent.com --certificate-identity-regexp https://github.com/intel/<repo>/.github/workflows/lib-publish.yaml.* intel/<image>:<version>  | jq .
```

To verify the signing in Kubernetes, one can use [policy managers](https://docs.sigstore.dev/policy-controller/overview/) with [keyless authorities](https://docs.sigstore.dev/policy-controller/overview/#configuring-keyless-authorities).

### Kubernetes ServiceAccount Permissions

When running in Kubernetes, the pck-cert-tool requires specific RBAC permissions managed by the operator.

#### For get-platforms command:
- `secrets`: `get`, `create`, `patch` (to create/update secrets with platform data)

#### For get-certificates command:
- `secrets`: `get`, `watch` (to read and watch for certificate updates)

#### For register command:
- `secrets`: `get`, `create`, `patch`, `watch`, `list` (to watch platform-data secrets and create PCK secrets)
