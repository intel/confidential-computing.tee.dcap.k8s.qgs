# DCAP Operator

A Kubernetes operator for managing Intel TDX DCAP (Data Center Attestation Primitives) infrastructure. Built with [kube-rs](https://kube.rs/).

## Overview

This operator automates the deployment and lifecycle management of TDX Quote Generation Service (QGS) across Kubernetes clusters, handling platform registration and PCK certificate provisioning in both online and offline modes.

## Building

### Build the Operator Binary

```bash
# From workspace root
cargo build --release -p operator
```

### Build the Docker Image

See [DOCKER.md](../../DOCKER.md) for full build instructions.

## Deployment

### Quick Start

Deploy everything with kustomize:

```bash
kubectl apply -k deployment/default
```

This creates:
- Namespace: `intel-dcap-operator-system`
- CRD: `tdxquotegenerationservices.trustedservices.intel.com`
- RBAC: ClusterRole, ClusterRoleBinding
- Deployment: `intel-tdx-dcap-controller-manager`

Verify deployment:

```bash
kubectl get pods -n intel-dcap-operator-system
```

### Deploy a TdxQuoteGenerationService

For a first end-to-end deployment in Online mode, see [QUICKSTART.md](../../QUICKSTART.md). Offline mode follows the same steps but applies `deployment/samples/offline-mode.yaml` and requires no Intel PCS API key.

**External Mode (externally managed platform registration):**

When PCK Certificate secrets are managed by an external system:

```bash
kubectl apply -f deployment/samples/external-mode.yaml
kubectl get tqgs intel-tdx-dcap-external
```

This mode:
- Does not create registrar Deployment
- Does not create platform-registration initContainer to collect platform manifest
- Does not mount efivars volume
- Requires PCK certificate secrets to be provisioned externally before QGS pods can sign
  quotes, named `<node-name>-pck`

## Common Operations

### Viewing Resources

```bash
# List all TdxQuoteGenerationService resources
kubectl get tqgs

# Describe a resource
kubectl describe tqgs intel-tdx-dcap

# Check created DaemonSets
kubectl get daemonsets -l app=intel-tdx-qgs

# Check registrar Deployment (Online mode only)
kubectl get deployments -l app=intel-tdx-registrar

# List PCK certificate secrets
kubectl get secrets -l fmspc --show-labels

# List platform-data secrets
kubectl get secrets -l type=platform-data --show-labels
```

### Updating Operator

**Using kustomize:**

```bash
cd deployment/default
kustomize edit set image intel-tdx-dcap-operator=myregistry.example.com/intel-tdx-dcap-operator:v1.0.0
kubectl apply -k .
```

**Using kubectl directly:**

```bash
kubectl set image deployment/intel-tdx-dcap-controller-manager \
  operator=myregistry.example.com/intel-tdx-dcap-operator:v1.0.0 \
  -n intel-dcap-operator-system
```

### Cleanup

```bash
# Delete all TdxQuoteGenerationService resources
kubectl delete tqgs --all

# Uninstall operator
kubectl delete -k deployment/default
```

## Customization

### Change Namespace

Edit `deployment/default/kustomization.yaml`:

```yaml
namespace: my-custom-namespace
```

### Adjust Resources

Edit `deployment/manager/manager.yaml`:

```yaml
resources:
  limits:
    cpu: 1000m
    memory: 512Mi
  requests:
    cpu: 200m
    memory: 256Mi
```

## Advanced Deployment

### Using kubectl (without kustomize)

Apply manifests individually:

```bash
# 1. Create CRD
kubectl apply -f deployment/crd/tdxquotegenerationservice-crd.yaml

# 2. Create namespace
kubectl apply -f deployment/manager/namespace.yaml

# 3. Create RBAC
kubectl apply -f deployment/rbac/

# 4. Create operator deployment
kubectl apply -f deployment/manager/manager.yaml
```

### Preview Generated Manifests

```bash
kubectl kustomize deployment/default
```

### Dry Run

```bash
kubectl apply -k deployment/default --dry-run=client
```

## Troubleshooting

### Operator Not Starting

Check pod status:

```bash
kubectl get pods -n intel-dcap-operator-system
kubectl describe pod -n intel-dcap-operator-system -l app.kubernetes.io/name=intel-dcap-operator
```

### RBAC Permission Issues

Verify RBAC permissions:

```bash
kubectl auth can-i create daemonsets \
  --as=system:serviceaccount:intel-dcap-operator-system:default
```

### CRD Issues

Verify CRD installation:

```bash
kubectl get crd tdxquotegenerationservices.trustedservices.intel.com
```

### Resource Creation Failures

Debug a TdxQuoteGenerationService:

```bash
kubectl describe tqgs intel-tdx-dcap
kubectl get events --sort-by='.lastTimestamp' | grep -i tdx
```

## RBAC Permissions

The system has two levels of RBAC:

### **1. Operator ClusterRole + Role**

The operator uses two separate RBAC resources:

**ClusterRole** (`deployment/rbac/cluster_role.yaml`) — cluster-scoped CRD access only:
- **TdxQuoteGenerationService**: get, list, watch, create, update, patch, delete + status + finalizers

**Role** (`deployment/rbac/role.yaml`) — namespace-scoped resources in `intel-dcap-operator-system`:
- **DaemonSets**: full CRUD + delete (explicit delete when switching modes)
- **Deployments**: full CRUD + delete (explicit delete when switching to Offline)
- **Secrets**: get, list, watch, create, patch

**Note:** The operator uses the `default` ServiceAccount in `intel-dcap-operator-system`. It does not create or manage ServiceAccounts, Roles, or RoleBindings at runtime — the `qgs` ServiceAccount/Role/RoleBinding used by QGS/registrar pods (see below) are static manifests applied once via `kubectl apply -k deployment/default`, not reconciled by the controller.

### **2. Pod Role (statically deployed)**

`deployment/rbac/intel-tdx-dcap-role.yaml` defines a namespaced Role for QGS/registrar pods:

```yaml
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: [get, list, watch, create, patch]
```

**pck-cert-tool Operations:**

| Command | Secrets Operations | Verbs Needed |
|---------|-------------------|--------------|
| **get-platforms** | Creates platform-data secrets | create, patch |
| **register** | Watches platform-data, creates PCK certs | get, list, watch, create, patch |
| **get-certificates** | Reads PCK certs, watches updates | get, watch |

## Running Locally

For development and testing:

```bash
# Set the target namespace
export OPERATOR_NAMESPACE=default

# Run against your current kubectl context
cargo run -p operator
```

## Testing

```bash
cargo test -p operator
```

## Environment Variables

- `OPERATOR_NAMESPACE` - Namespace where the operator creates resources (set via Downward API `fieldRef`; defaults to `default` if unset)
- `QGS_SERVICE_ACCOUNT` - Name of the ServiceAccount used by QGS/registrar pods the operator creates (set by kustomize from the `qgs` ServiceAccount name; defaults to `intel-tdx-dcap-qgs` if unset)
- `RELATED_IMAGE_QGS` - Overrides the image used for all DaemonSet containers (platform-registration initContainer, pck-certs-watcher sidecar, tdx-qgs). Follows the OLM `RELATED_IMAGE_*` convention so operator-sdk includes it in `relatedImages` when generating the bundle
- `HTTPS_PROXY` / `https_proxy` - If set on the operator process, propagated into the registrar Deployment's container env so it can reach Intel PCS through a proxy

## Project Structure

```
operator/
├── Cargo.toml
├── build/operator/Dockerfile  # Multi-stage build with static binary
├── Makefile                # Build, test, and bundle targets
├── PROJECT                 # operator-sdk project metadata
├── src/
│   ├── main.rs            # Entry point with signal handling
│   ├── lib.rs             # Library exports
│   ├── error.rs           # Error types
│   └── tdx_quote_generation_service/
│       ├── controller.rs  # Reconciliation logic
│       ├── types.rs       # CRD types
│       └── mod.rs
├── templates/             # DaemonSet and Deployment templates
└── deployment/            # Kubernetes deployment manifests
    ├── crd/
    ├── rbac/
    ├── manager/
    ├── samples/
    ├── default/
    ├── manifests/         # OLM kustomize bases (CSV base + kustomization.yaml)
    └── bundle/            # Generated OLM bundle (git-ignored)
```

## OLM Bundle

The operator can be packaged as an [OLM bundle](https://olm.operatorframework.io/) for distribution via OperatorHub or a private catalog.

### Prerequisites

- [operator-sdk](https://sdk.operatorframework.io/docs/installation/)
- [kustomize](https://kubectl.docs.kubernetes.io/installation/kustomize/)

### Generating the bundle

```bash
make bundle VERSION=0.1.0
```

Generates the CSV kustomize base in `deployment/manifests/bases/`, builds the bundle via `kustomize build | operator-sdk generate bundle`, and validates it. Output is written to `deployment/bundle/`.

UI metadata (display name, description, keywords, maintainers) is stored in `deployment/manifests/bases/operator.clusterserviceversion.yaml` — edit that file to update it.

### Channels and versioning

```bash
make bundle VERSION=1.0.0 CHANNELS=stable DEFAULT_CHANNEL=stable
```

### Building and pushing the bundle image

```bash
docker build -f bundle.Dockerfile -t $(BUNDLE_IMG) deployment/bundle
docker push $(BUNDLE_IMG)
```

### Installing via OLM

```bash
operator-sdk olm install
operator-sdk run bundle $(BUNDLE_IMG)
```

## Security

The deployment includes security best practices:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 65532
  fsGroup: 65532

containerSecurityContext:
  allowPrivilegeEscalation: false
  capabilities:
    drop: [ALL]
  readOnlyRootFilesystem: true
```
