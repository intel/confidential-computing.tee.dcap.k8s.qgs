# DCAP Operator

A Kubernetes operator for managing Intel TDX DCAP (Data Center Attestation Primitives) infrastructure. Built with [kube-rs](https://kube.rs/).

## Overview

This operator automates the deployment and lifecycle management of TDX Quote Generation Service (QGS) across Kubernetes clusters, handling platform registration and PCK certificate provisioning in both online and offline modes.

## Prerequisites

- Rust 1.75 or later
- kubectl configured with cluster access
- Docker (for building container images)
- Kubernetes cluster with SGX/TDX-capable worker nodes

## Building

### Build the Operator Binary

```bash
# From workspace root
cargo build --release -p operator
```

### Build the Docker Image

Multi-stage build (see [DOCKER.md](../../DOCKER.md) for full details). Build from the **repo root**:

```bash
docker build -t intel-tdx-dcap-operator:latest -f build/operator/Dockerfile .
```

**Push to registry:**

```bash
docker tag intel-tdx-dcap-operator:latest myregistry.example.com/intel-tdx-dcap-operator:v1.0.0
docker push myregistry.example.com/intel-tdx-dcap-operator:v1.0.0
```

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

**Online Mode (with Intel PCS):**

```bash
# 1. Create API key secret
kubectl create secret generic intel-pcs-api-key \
  --from-literal=api-key=YOUR_INTEL_API_KEY

# 2. Deploy CR
kubectl apply -f deployment/samples/online-mode.yaml

# 3. Check status
kubectl get tqgs intel-tdx-dcap
```

**Offline Mode (air-gapped):**

```bash
kubectl apply -f deployment/samples/offline-mode.yaml
kubectl get tqgs intel-tdx-dcap
```

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
- Requires PCK certificate secrets to be provisioned externally before QGS pods can sign quotes

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

### Change Image

Edit `deployment/default/kustomization.yaml`:

```yaml
images:
- name: intel-tdx-dcap-operator
  newName: myregistry.example.com/intel-tdx-dcap-operator
  newTag: v1.0.0
```

Then apply:

```bash
kubectl apply -k deployment/default
```

### Change Namespace

Edit `deployment/default/kustomization.yaml`:

```yaml
namespace: my-custom-namespace
```

### Adjust Resources

Edit `deployment/manager/deployment.yaml`:

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
kubectl apply -f deployment/manager/deployment.yaml
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
- **ServiceAccounts**: get, list, watch, create, update, patch (GC via ownerRef)
- **Roles**: get, list, watch, create, update, patch (GC via ownerRef)
- **RoleBindings**: get, list, watch, create, update, patch (GC via ownerRef)

**Note:** The operator uses the `default` ServiceAccount in `intel-dcap-operator-system`. It creates dedicated ServiceAccounts for the QGS/registrar pods it manages.

### **2. Pod Role (created by operator)**

The operator creates a namespaced Role for QGS/registrar pods:

```yaml
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: [get, create, list, patch, watch]
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

- `OPERATOR_NAMESPACE` - Namespace where the operator creates resources (set via Downward API)

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

## Production Considerations

### Image Registry

```bash
docker tag intel-tdx-dcap-operator:latest myregistry.example.com/intel-tdx-dcap-operator:v1.0.0
docker push myregistry.example.com/intel-tdx-dcap-operator:v1.0.0

cd deployment/default
kustomize edit set image intel-tdx-dcap-operator=myregistry.example.com/intel-tdx-dcap-operator:v1.0.0
kubectl apply -k .
```

### Resource Limits

Adjust based on cluster size:

```yaml
resources:
  limits:
    cpu: 500m      # Increase for large clusters
    memory: 256Mi  # Increase if managing many CRs
```

### High Availability

For HA deployment:
1. Implement leader election (using leases)
2. Update deployment replicas to 2-3
3. Add pod anti-affinity rules

## Uninstall

```bash
# Delete all CRs
kubectl delete tqgs --all

# Delete operator
kubectl delete -k deployment/default
```

## Support

- Review this README for operator documentation
- Check [pck-cert-tool README](../pck-cert-tool/README.md) for certificate management
- Examine `templates/` directory for DaemonSet/Deployment configuration

## License

This project is licensed under the Apache License 2.0.
