# PCK Certificate Tool

A Rust utility for managing PCK certificates and platform data in Kubernetes.

## Commands

### get-platforms

Get platform data and create Kubernetes secrets with platform manifest data.

#### Features

- Reads platform manifest from EFI variable `SgxRegistrationServerRequest-304e0796-d515-4698-ac6e-e76cb1a71c28`
- Calls external platform info binary to get SGX platform information (CPU SVN, encrypted PPID, PCE ID, PCE SVN, QE ID)
- Creates or updates Kubernetes secrets with platform data
- Labels secrets with `type=platform-data` for easy identification

### register

Watch platform-data secrets and automatically register them with Intel PCS to obtain PCK certificates and TCB Info.

#### Features

- Watches all secrets labeled with `type=platform-data` in the specified namespace
- Automatically processes new or updated platform-data secrets
- Sends platform manifest, PCE ID, and CPU SVN to Intel Provisioning Certification Service (PCS) API
- Retrieves platform-specific PCK certificates from Intel PCS v4 API `/pckcerts/config` endpoint
- Retrieves SGX TCB Info using the FMSPC from the certificate response
- Creates binary cache files in SGX DCAP QPL format containing:
  - Cache header with 1-year expiration (8760 hours)
  - TCB component (platform-specific CPU SVN from secret data)
  - SGX TCB Info JSON
  - Certificate chain (URL-decoded PEM)
  - PCK certificates JSON array
- Creates new secrets with `-pck` suffix containing base64-encoded cache files
- Labels PCK secrets with `fmspc=<value>` extracted from the SGX-FMSPC response header
- Handles multiple concurrent registrations for parallel secret creation
- Uses `update=early` query parameter for TCB Info requests

### get-certificates

Get PCK certificates from a Kubernetes secret and write to a file, continuously watching for updates.

#### Features

- Reads a secret named `<qe_id>-pck` (where qe_id is obtained from the platform info binary)
- Writes certificate data to `<output_dir>/<qe_id>_0000`
- Watches the secret for updates and rewrites the file when changes occur
- Continues running and watching until interrupted

## Installation

Build the utility from the workspace root:

```bash
cargo build --release -p pck-cert-tool
```

The binary will be available at `target/release/pck-cert-tool`

## Usage

### get-platforms command

Get platform data and create Kubernetes secrets. The secret name is automatically derived from the QE ID.

Basic usage:

```bash
sudo ./target/release/pck-cert-tool get-platforms --platform-info-binary /path/to/get-platform-info
```

Specify a namespace:

```bash
sudo ./target/release/pck-cert-tool get-platforms --platform-info-binary /path/to/get-platform-info --namespace my-namespace
```

Short options:

```bash
sudo ./target/release/pck-cert-tool get-platforms -p /path/to/get-platform-info -n my-namespace
```

### register command

Watch for platform-data secrets and automatically register them with Intel PCS.

**Note:** You need an Intel PCS API key (subscription key) to use this command.

Basic usage:

```bash
./target/release/pck-cert-tool register --api-key YOUR_API_KEY
```

Specify a namespace:

```bash
./target/release/pck-cert-tool register --api-key YOUR_API_KEY --namespace my-namespace
```

Short options:

```bash
./target/release/pck-cert-tool register -a YOUR_API_KEY -n my-namespace
```

The register command will:
1. Watch for secrets with label `type=platform-data`
2. Extract platform manifest, PCE ID, and CPU SVN from each secret
3. Send a POST request to Intel PCS API `/pckcerts/config` endpoint with platform-specific CPU SVN to retrieve matching PCK certificates
4. Create a new secret named `<original_name>-pck` with the certificate data
5. Label the new secret with `fmspc=<value>` from the API response

### get-certificates command

Get PCK certificates from a Kubernetes secret and write to a file, watching for updates.

Basic usage:

```bash
./target/release/pck-cert-tool get-certificates --platform-info-binary /path/to/get-platform-info --output-dir /path/to/output
```

Specify a namespace:

```bash
./target/release/pck-cert-tool get-certificates --platform-info-binary /path/to/get-platform-info --output-dir /path/to/output --namespace my-namespace
```

Short options:

```bash
./target/release/pck-cert-tool get-certificates -p /path/to/get-platform-info -o /path/to/output -n my-namespace
```

The command will:
1. Get the QE ID by calling the specified binary
2. Look for a secret named `<qe_id>-pck` in the namespace
3. Extract the `certificate` field from the secret
4. Write it to `<output_dir>/<qe_id>_0000`
5. Continue watching for updates to the secret
6. Rewrite the file whenever the secret is updated

## Secret Data Format

The created secret will be named using the QE ID value and contain the following keys in stringData:

```yaml
metadata:
  name: <qe_id>
  labels:
    type: platform-data
stringData:
  cpu_svn: "<CPU security version number from platform info binary>"
  enc_ppid: ""
  pce_id: "<PCE ID from platform info binary>"
  pce_svn: "<PCE security version number from platform info binary>"
  qe_id: "<QE ID from platform info binary>"
  platform_manifest: "<hex-encoded platform manifest structure data>"
```

The `platform_manifest` field contains the structure data from the EFI variable `SgxRegistrationServerRequest`, hex-encoded as a string:
- **Structure data**: StructureHeader (32 bytes GUID + metadata) + manifest body
- **Header skipped**: The 4-byte prefix (version + size) is excluded
- **Storage format**: Text hex string in Kubernetes `stringData`

All values except platform_manifest are extracted from the JSON output of the platform info binary.

The secret is labeled with `type=platform-data` for easy identification and filtering.

## PCK Certificate Secret Format

When the `register` command processes a platform-data secret, it creates a new secret with `-pck` suffix:

```yaml
metadata:
  name: <qe_id>-pck
  labels:
    fmspc: "<FMSPC value from SGX-FMSPC header>"
data:
  certificate: <base64-encoded cache file>
```

The `certificate` field contains a binary cache file in the format used by Intel SGX DCAP Quote Provider Library (QPL). The cache file structure is:

1. **Cache Header** (14 bytes):
   - Version: `u16` (little-endian) = 1
   - Flags: `u32` (little-endian) = 4 (SGX_QPL_CACHE_MULTICERTS)
   - Expiration: `u64` (little-endian) = Unix timestamp + 8760 hours (1 year)

2. **TCB Component** (length-prefixed):
   - Length: `u32` (little-endian)
   - Data: 32-character hex string = platform-specific CPU SVN from secret's `cpu_svn` field

3. **SGX TCB Info** (length-prefixed):
   - Length: `u32` (little-endian)
   - Data: JSON from `/tcb?fmspc=<value>&update=early` endpoint

4. **Certificate Chain** (length-prefixed):
   - Length: `u32` (little-endian)
   - Data: URL-decoded PEM certificate chain from SGX-PCK-Certificate-Issuer-Chain header

5. **PCK Certificates** (length-prefixed):
   - Length: `u32` (little-endian)
   - Data: JSON array from `/pckcerts/config` endpoint response body (certificates matched to platform's CPU SVN)

This format is compatible with the SGX DCAP QPL cache and can be directly consumed by quote verification libraries.

The `fmspc` label contains the Family-Model-Stepping-Platform-Custom SKU value returned by Intel PCS, which identifies the platform's TCB (Trusted Computing Base) level.

## Platform Info Binary

The platform info binary must output a single-line JSON string to stdout with fields `cpu_svn`, `enc_ppid`, `pce_id`, `pce_svn`, and `qe_id` (all hex strings), and exit with code 0 on success. See [bin/get-platform-info/README.md](../get-platform-info/README.md) for the reference implementation and full output specification.

## Examples

### Complete Workflow Example

1. **Create platform data secret:**

```bash
sudo ./target/release/pck-cert-tool get-platforms -p /usr/local/bin/get_platform_info -n default
```

This creates a secret with name matching the QE ID (e.g., `a1b2c3d4e5f6`) labeled with `type=platform-data`.

2. **Register with Intel PCS (in a separate terminal or as a service):**

```bash
./target/release/pck-cert-tool register -a YOUR_INTEL_API_KEY -n default
```

This watches for platform-data secrets and automatically:
- Detects the new `a1b2c3d4e5f6` secret
- Sends platform manifest and PCE ID to Intel PCS
- Retrieves PCK certificates
- Retrieves SGX TCB Info using the FMSPC from the certificate response
- Creates binary cache file in SGX DCAP QPL format
- Creates `a1b2c3d4e5f6-pck` secret with base64-encoded cache file
- Labels it with `fmspc=<value>`

3. **Write certificates to filesystem:**

```bash
./target/release/pck-cert-tool get-certificates -p /usr/local/bin/get_platform_info -o /var/lib/certs -n default
```

This reads the `a1b2c3d4e5f6-pck` secret and writes `/var/lib/certs/a1b2c3d4e5f6_0000` (binary cache file compatible with SGX DCAP QPL).

### get-platforms example

Running:

```bash
sudo ./target/release/pck-cert-tool get-platforms -p /usr/local/bin/get_platform_info -n default
```

If the platform info binary outputs a QE ID of `a1b2c3d4e5f6`, this will create/update a secret named `a1b2c3d4e5f6` with platform manifest data.

### register example

Running:

```bash
./target/release/pck-cert-tool register -a 1234567890abcdef -n default
```

The register service will:
- Watch for any secret with label `type=platform-data`
- When `a1b2c3d4e5f6` secret is created, automatically process it
- Extract platform-specific CPU SVN from the secret
- Retrieve platform-matched PCK certificates from Intel PCS `/pckcerts/config` endpoint
- Retrieve SGX TCB Info using the FMSPC value
- Create binary cache file in SGX DCAP QPL format with platform's CPU SVN in TCB component
- Create `a1b2c3d4e5f6-pck` secret with base64-encoded cache file
- Continue watching for more platform-data secrets

### get-certificates example

Running:

```bash
./target/release/pck-cert-tool get-certificates -p /usr/local/bin/get_platform_info -o /var/lib/certs -n default
```

If the QE ID is `a1b2c3d4e5f6`:
- Looks for secret named `a1b2c3d4e5f6-pck`
- Writes binary cache file to `/var/lib/certs/a1b2c3d4e5f6_0000`
- Watches for updates and rewrites the file when the secret changes

## Retrieving the Secret

View the secret (assuming QE ID is `a1b2c3d4e5f6`):

```bash
kubectl get secret a1b2c3d4e5f6 -n default -o yaml
```

List all platform data secrets:

```bash
kubectl get secrets -l type=platform-data -n default
```

Decode specific fields:

```bash
kubectl get secret a1b2c3d4e5f6 -n default -o jsonpath='{.data.qe_id}' | base64 -d
kubectl get secret a1b2c3d4e5f6 -n default -o jsonpath='{.data.platform_manifest}' | base64 -d
```
