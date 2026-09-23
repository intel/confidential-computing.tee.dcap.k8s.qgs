# Quickstart

This walks through a first end-to-end deployment of the TDX Quote Generation Service (QGS) and PCK certificate provisioning in **Online mode**.

## Prerequisites

- A Kubernetes cluster with SGX/TDX-capable worker nodes.
- The [Intel SGX device plugin](https://github.com/intel/intel-device-plugins-for-kubernetes/blob/main/cmd/sgx_plugin/README.md) deployed, so that `sgx.intel.com/enclave` and `sgx.intel.com/provision` resources are advertised on those nodes. QGS pods request these resources.
- Cluster admin has configured Pod Security Admission and Resource Quotas to prevent unwanted QGS hostPath volume access and/or `sgx.intel.com/*` resource use (see [DOCKER.md](DOCKER.md)).
- Worker nodes labeled to identify SGX/TDX-capable nodes, so they can be targeted with `nodeSelector`. An explicit `nodeSelector` is recommended over relying solely on the `sgx.intel.com/*` resource requests, so QGS placement doesn't depend on which nodes happen to advertise those resources. **No specific label is required or assumed** — `nodeSelector` is fully configurable to match whatever labeling scheme your cluster uses (e.g. one applied by [Node Feature Discovery](https://kubernetes-sigs.github.io/node-feature-discovery/)). The samples below use `intel.feature.node.kubernetes.io/sgx=true` as an example only.
- An [Intel PCS API key](https://api.portal.trustedservices.intel.com/) (Optional, Online mode only).
- Container images: use the published release images by default. Building from source is only needed for local development or unreleased changes — see [Building images from source](#building-images-from-source-developers) below.

> **Note:** Intel PCS enforces rate limiting on all requests. When using a personal API key for the requests, the rate limiting is enforced on this API key. In contrast, all anonymous users share the same rate limit. Thus, it is advisable to use a caching service and a personal API key in production environments.

## Deployment options

### Option A: Kubernetes operator (current)

1. **Deploy the operator:**

   ```bash
   kubectl apply -k bin/operator/deployment/default
   ```

2. **Create the Intel PCS API key secret** (Online mode only):

   ```bash
   kubectl create secret generic intel-pcs-api-key \
     --from-literal=api-key=YOUR_INTEL_API_KEY \
     --namespace intel-dcap-operator-system
   ```

3. **Label your SGX/TDX-capable nodes** (recommended, so you can explicitly target them with `nodeSelector` rather than relying only on `sgx.intel.com/*` resource requests):

   ```bash
   kubectl label nodes <node-name> intel.feature.node.kubernetes.io/sgx=true
   ```

4. **Deploy a TdxQuoteGenerationService:**

   ```bash
   kubectl apply -f bin/operator/deployment/samples/online-mode.yaml
   ```

   See [bin/operator/README.md](bin/operator/README.md) for Offline and External mode samples, and other deployment/customization options.

5. **Verify:**

   ```bash
   # Operator and QGS pods
   kubectl get pods -n intel-dcap-operator-system -l 'app in (intel-tdx-qgs,intel-tdx-registrar)'

   # Platform data secrets
   kubectl get secrets -n intel-dcap-operator-system -l type=platform-data

   # PCK certificate secrets
   kubectl get secrets -n intel-dcap-operator-system -l fmspc --show-labels

   # Certificates mounted in a QGS pod
   POD_NAME=$(kubectl get pod -n intel-dcap-operator-system -l app=intel-tdx-qgs -o name | head -1)
   kubectl exec -n intel-dcap-operator-system -it $POD_NAME -- ls -la /run/dcap/cache/.dcap-qcnl/
   ```

### Option B: Helm chart (without the operator)

Planned — a Helm-based deployment that runs QGS and PCK certificate provisioning directly, without the operator/CRD, will be documented here once available.

## Building images from source (developers)

Only needed for local development, testing unreleased changes, or contributing — most users should use the published release images instead. See [DOCKER.md](DOCKER.md) for details.

```bash
docker build -t intel-tdx-qgs:latest -f build/tdx-qgs/Dockerfile .
docker build -t intel-tdx-dcap-operator:latest -f build/operator/Dockerfile .
```

## Further reading

- [pck-cert-tool README](bin/pck-cert-tool/README.md) — CLI internals, secret/cache formats, PCS API details
- [Operator README](bin/operator/README.md) — full deployment, customization, and troubleshooting guide
- [DOCKER.md](DOCKER.md) — container build and security notes
