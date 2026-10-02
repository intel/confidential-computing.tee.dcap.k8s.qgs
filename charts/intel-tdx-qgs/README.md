# Intel® TDX DCAP Helm Chart

Helm chart that installs Intel® TDX DCAP Quote Generation Service (QGS) workloads directly, 
without an operator or custom resources.

This chart installs:
- Intel® SGX Device plugin as chart dependency
- QGS DaemonSet
- QGS ServiceAccount and namespaced Secret RBAC
- Registrar Deployment in `Online` mode
- Optional PCS API key Secret in `Online` mode

## Prerequisites

### Deploy External Components

1. Export release version:

    ```bash
    export INTEL_DEVICE_PLUGIN_VER=release-0.37
    ```

2. Deploy NFD

    ```bash
    kubectl apply -k "https://github.com/intel/intel-device-plugins-for-kubernetes/deployments/nfd?ref=$INTEL_DEVICE_PLUGIN_VER"
    ```

3. Deploy NodeFeatureRules

    ```bash
    kubectl apply -k "https://github.com/intel/intel-device-plugins-for-kubernetes/deployments/nfd/overlays/node-feature-rules?ref=$INTEL_DEVICE_PLUGIN_VER"
    ```

4. Verify the NFD is working and SGX feature is detected:

    ```bash
    kubectl get no -o json | jq .items[].metadata.labels | grep intel.feature.node.kubernetes.io/sgx
    ```

To install all external components required for full deployment use [this documentation](../STACK_DEPLOYMENT.md).

### Select SGX/TDX-capable nodes

The chart does not assume any node label. Set `global.nodeSelector` to labels that identify the SGX/TDX-capable
nodes, for example the label applied by the NodeFeatureRules above:

```bash
--set-string global.nodeSelector.intel\.feature\.node\.kubernetes\.io/sgx=true
```

`global.nodeSelector` is used by both the QGS DaemonSet and the SGX device plugin sub-chart. Without a node selector,
both are scheduled on all nodes, and their pods cannot start on nodes without SGX/TDX.

Instead of deploying the NodeFeatureRules above, the SGX device plugin sub-chart can create a NodeFeatureRule that
applies the `global.nodeSelector` labels to SGX-capable nodes (NFD must be installed):

```bash
--set intel-sgx-plugin.nodeFeatureRule.enabled=true \
--set-string global.nodeSelector.intel\.feature\.node\.kubernetes\.io/sgx=true
```

The rule is cluster-scoped, so installing requires permission to create `nodefeaturerules.nfd.k8s-sigs.io`.
By default, NFD only creates labels in the `feature.node.kubernetes.io` and `*.feature.node.kubernetes.io` namespaces.

### Prepare a dedicated namespace

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

The Intel PCS API key is optional. The registrar reads it from the Secret named by `pcsApiKey.secretName`
(default `intel-pcs-api-key`, data key `api-key`); if the Secret does not exist, PCS requests are made without a key.

> **Note:** Intel PCS enforces rate limiting on all requests. When using a personal API key for the requests, the rate limiting is enforced on this API key. In contrast, all anonymous users share the same rate limit. Thus, it is advisable to use a caching service and a personal API key in production environments.

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

Install Online mode. The default `pcsApiKey.secretName` references the Secret created above;
set `--set pcsApiKey.secretName=<name>` to use a Secret with a different name:

```bash
helm dependency update ./charts/intel-tdx-qgs

helm upgrade --install intel-tdx-dcap ./charts/intel-tdx-qgs \
  --namespace "$DCAP_NAMESPACE" \
  --set tdxQuoteGenerationService.mode=Online
```

Alternatively, let the chart create the Secret with `--set pcsApiKey.apiKey=...`.

> **Warning:** Helm stores supplied values unencrypted in its release Secrets, so the key is visible via
> `helm get values` to anyone who can read Secrets in the namespace, and it remains in old revisions after rotation.
> Prefer creating the Secret outside Helm for production credentials.


## Offline Mode

```bash
helm dependency update ./charts/intel-tdx-qgs

helm upgrade --install intel-tdx-dcap ./charts/intel-tdx-qgs \
  --namespace "$DCAP_NAMESPACE" \
  --set tdxQuoteGenerationService.mode=Offline
```

## External Mode

```bash
helm dependency update ./charts/intel-tdx-qgs

helm upgrade --install intel-tdx-dcap ./charts/intel-tdx-qgs \
  --namespace "$DCAP_NAMESPACE" \
  --set tdxQuoteGenerationService.mode=External
```

## Published chart

Released chart versions are published to `oci://ghcr.io/intel/intel-tdx-qgs`. To use the published chart,
replace `./charts/intel-tdx-qgs` with `oci://ghcr.io/intel/intel-tdx-qgs --version <version>` in the commands above
(`helm dependency update` is not needed).

## Modes

- `Offline` (default): QGS and the platform-registration init container; no registrar.
- `Online`: QGS, platform-registration init container, and registrar Deployment.
- `External`: QGS without the platform-registration init container or EFI variables mount;
  registration and PCK certificate Secrets are managed externally.

The chart applies `app.kubernetes.io/mode` to managed resources (not to pod templates).
Its value is normalized to `online`, `offline`, or `external`. 
For example, list workloads installed in Offline mode with:

```bash
kubectl get daemonsets,deployments \
  --namespace "$DCAP_NAMESPACE" \
  --selector app.kubernetes.io/mode=offline
```

## Values

The chart's default configuration is defined in [values.yaml](./values.yaml).
By default, the chart uses the `docker.io/intel/intel-tdx-qgs` image tagged with the chart `appVersion`;
override it with `image.repository` and `image.tag`. Released charts also pin the image by digest
(`image.digest`); set `image.digest=""` when overriding the image tag or repository.

The chart installs the Intel SGX device plugin as a sub-chart. Set `intel-sgx-plugin.enabled=false` if the plugin
is already deployed in the cluster. Other `intel-sgx-plugin.*` values are passed to the sub-chart; list them with
`helm show values oci://ghcr.io/intel/intel-sgx-device-plugin`.
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
