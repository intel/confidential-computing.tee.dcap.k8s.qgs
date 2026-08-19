.PHONY: bundle generate

# Project settings
PROJECT_NAME := intel-tdx-dcap-operator

# Bundle settings
VERSION ?= 0.0.1
CHANNELS ?= alpha
DEFAULT_CHANNEL ?= alpha
BUNDLE_METADATA_OPTS ?= --channels=$(CHANNELS) --default-channel=$(DEFAULT_CHANNEL)
KUSTOMIZE_DIR := deployment/manifests
BUNDLE_DIR := deployment/bundle

CRD_FILE := deployment/crd/tdxquotegenerationservice-crd.yaml

# Regenerate CRD YAML from Rust types
generate:
	cargo run --bin generate_crd > $(CRD_FILE)

# Generate OLM bundle. Override VERSION, CHANNELS, DEFAULT_CHANNEL as needed.
bundle:
	operator-sdk generate kustomize manifests \
		--input-dir=$(KUSTOMIZE_DIR) \
		--output-dir=$(KUSTOMIZE_DIR) \
		--package=$(PROJECT_NAME)
	kustomize build $(KUSTOMIZE_DIR) | operator-sdk generate bundle \
		--version=$(VERSION) \
		--package=$(PROJECT_NAME) \
		--output-dir=$(BUNDLE_DIR) \
		--overwrite \
		--extra-service-accounts intel-tdx-dcap-qgs \
		$(BUNDLE_METADATA_OPTS)
	operator-sdk bundle validate $(BUNDLE_DIR)
