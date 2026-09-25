# Intel® TDX DCAP Helm Chart

Helm chart that installs Intel® TDX DCAP Quote Generation Service (QGS) workloads directly, 
without an operator or custom resources.

This chart installs:
- QGS DaemonSet
- QGS ServiceAccount and namespaced Secret RBAC
- Registrar Deployment in `Online` mode
- Optional PCS API key Secret in `Online` mode

## Prerequisites

The chart does **not** install these external components:
- Node Feature Discovery (NFD) + NodeFeatureRules
- Intel Device Plugins Operator + SGX device plugin
- SGX-capable nodes with label `intel.feature.node.kubernetes.io/sgx=true`

To install all external components required for full deployment use [this documentation](../STACK_DEPLOYMENT.md).

## Prepare a dedicated namespace

The current QGS pod specification cannot run under the `baseline` or `restricted` Pod Security Standards. 
It uses a host path for the QGS socket in all modes; `Online` and `Offline` modes additionally use a privileged platform 
registration init container and mount host EFI variables.

Create a dedicated namespace before installing the chart. 
Do not deploy unrelated workloads in this namespace:

```bash
export DCAP_NAMESPACE=intel-dcap-operator-system

cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Namespace
metadata:
  name: ${DCAP_NAMESPACE}
  labels:
    app.kubernetes.io/part-of: intel-tdx-qgs
    pod-security.kubernetes.io/enforce: privileged
    pod-security.kubernetes.io/enforce-version: latest
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/audit-version: latest
    pod-security.kubernetes.io/warn: restricted
    pod-security.kubernetes.io/warn-version: latest
EOF
```

`enforce=privileged` is required by the current workload; it is not a general security recommendation.<br>
`audit=restricted` and `warn=restricted` make policy exceptions visible without blocking QGS. 

Because Pod Security Admission labels apply to every pod in a namespace:

- grant permission to create Pods, DaemonSets, Deployments, Jobs, or RBAC in this namespace only to the chart installer and trusted administrators;
- do not bind broad groups such as `system:authenticated` to write roles;
- use an admission-policy engine, where available, to restrict images, service accounts, privileged containers, and allowed host paths to this release;
- protect etcd with encryption at rest and limit `get`, `list`, and `watch` access to Secrets;
- apply cluster-specific egress policy so only required PCS or proxy endpoints are reachable in `Online` mode.

Verify the namespace labels before installation:

```bash
kubectl get namespace "$DCAP_NAMESPACE" --show-labels
kubectl auth can-i create daemonsets.apps --namespace "$DCAP_NAMESPACE"
kubectl auth can-i create roles.rbac.authorization.k8s.io --namespace "$DCAP_NAMESPACE"
```

Both authorization checks must return `yes` for the identity installing this chart. 
Namespace creation and Pod Security label changes should remain limited to cluster administrators.

## Online Mode

Create the PCS API key Secret outside Helm. This avoids placing the key in the command line and in Helm release values:

```bash
read -rsp 'Intel PCS API key: ' PCCS_API_KEY && echo
printf '%s' "$PCCS_API_KEY" \
  | kubectl create secret generic intel-pcs-api-key \
      --namespace "$DCAP_NAMESPACE" \
      --from-file=api-key=/dev/stdin \
      --dry-run=client \
      --output yaml \
  | kubectl apply -f -
unset PCCS_API_KEY
```

Install Online mode and reference the existing Secret:

```bash
helm upgrade --install intel-tdx-dcap ./charts/intel-tdx-qgs \
  --namespace "$DCAP_NAMESPACE" \
  --set tdxQuoteGenerationService.mode=Online \
  --set pcsApiKey.apiKey=...
```

Do not use `--set pcsApiKey.apiKey=...` for production credentials: Helm stores supplied values in its release Secret.


## Offline Mode

```bash
helm upgrade --install intel-tdx-dcap ./charts/intel-tdx-qgs \
  --namespace "$DCAP_NAMESPACE" \
  --set tdxQuoteGenerationService.mode=Offline
```

## External Mode

```bash
helm upgrade --install intel-tdx-dcap ./charts/intel-tdx-qgs \
  --namespace "$DCAP_NAMESPACE" \
  --set tdxQuoteGenerationService.mode=External
```

## Modes

- `Offline` (default): QGS and the platform-registration init container; no registrar.
- `Online`: QGS, platform-registration init container, and registrar Deployment.
- `External`: QGS without the platform-registration init container or EFI variables mount;
  registration and PCK certificate Secrets are managed externally.

The chart applies `app.kubernetes.io/mode` to managed resources and pod templates. 
Its value is normalized to `online`, `offline`, or `external`. 
For example, list workloads installed in Offline mode with:

```bash
kubectl get daemonsets,deployments \
  --namespace "$DCAP_NAMESPACE" \
  --selector app.kubernetes.io/mode=offline
```

## Values

The chart's default configuration is defined in [values.yaml](./values.yaml).
Override values with one or more values files using `--values`/`-f`, or use `--set` and `--set-string` for individual command-line overrides. 
Values files are merged in the order supplied, and command-line overrides take precedence.

Review the effective configuration before installation with `helm template` or `helm upgrade --install --dry-run`. 
Keep credentials out of values files and command-line arguments; create Kubernetes Secrets separately and configure the chart to reference them.

### Usage

1. Download helm chart values and save as `values.yaml`

    ```bash
    helm show values ./charts/intel-tdx-qgs > values.yaml
    ```

2. Verify default configuration and align to your needs

3. Install/update helm chart using saved file

    ```bash
    helm upgrade --install intel-tdx-dcap ./charts/intel-tdx-qgs \
    --namespace "$DCAP_NAMESPACE" \
    -f values.yaml
    ```

## Uninstall

```bash
helm uninstall intel-tdx-dcap --namespace "$DCAP_NAMESPACE"
```

This removes all chart-managed workloads, namespaced RBAC, and chart-created Secrets. 
It does not delete the namespace or an externally managed PCS API key Secret.

After confirming that no other resources use the namespace, a cluster administrator can remove it explicitly:

```bash
kubectl delete namespace "$DCAP_NAMESPACE"
```
