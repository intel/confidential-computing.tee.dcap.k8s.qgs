# Intel® TDX QGS umbrella Helm Chart

Umbrella helm chart that automates Intel® TDX QGS setup.

Umbrella helm chart will deploy TDX QGS with all required prerequisites:

- NFD + NodeFeatureRules
- Certificate manager
- Intel® Device Plugins Operator + SGX Device plugin
- Intel® TDX QGS

## Prerequisites

1. Install [helm](https://helm.sh/docs/intro/install/)

2. Install helm plugin `helm-diff`
    ```bash
    helm plugin install https://github.com/databus23/helm-diff --verify=false
    ```

3. Install [Helmfile](https://helmfile.readthedocs.io/)
    ```bash
    curl -LO https://github.com/helmfile/helmfile/releases/download/v1.8.0/helmfile_1.8.0_linux_amd64.tar.gz && \
    tar -xzf helmfile_1.8.0_linux_amd64.tar.gz && \
    chmod +x helmfile && \
    sudo mv helmfile /usr/local/bin/helmfile && \
    rm helmfile_1.8.0_linux_amd64.tar.gz
    ```

4. Verify `helmfile` installation
    ```bash
    helmfile --version
    ```

## Installation steps

By default **Online** mode is used which requires environment variable defined below. 

`*.gotmpl` file extension allows to pass environment variables to chart.  

1. [Online mode] Export PCS API Key
    ```bash
    export PCCS_API_KEY=<YOUR_PCCS_API_KEY>
    ```

2. Perform basic installation
    ```bash
    helmfile apply
    ```
   
### Advanced usage

To override default values for online mode (requires PCS API Key) use below command

```bash
helmfile \
  --state-values-set dcapValuesFile=./helmfile-qgs-values/<YOUR_CONFIG_FILE> \
  apply
```

Where `<YOUR_CONFIG_FILE>` is path to your custom values file. 
You can find example values files in `helmfile-qgs-values` folder.

## Uninstall

To uninstall umbrella helm chart and all its dependencies, run the following command:

```bash
helmfile destroy
```

## Troubleshooting

If any subchart fail try to manually sync it using below command:

```bash
helmfile sync --selector name=<NAME>
```

Where `<NAME>` can be:
- nfd
- cert-manager
- device-plugins-operator
- sgx-plugin
- intel-tdx-qgs
