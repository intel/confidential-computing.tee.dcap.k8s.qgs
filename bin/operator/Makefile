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

# Image settings. Override with pinned registry/digest values for releases, e.g.:
#   make bundle VERSION=0.1.0 REGISTRY=ghcr.io/intel
REGISTRY ?= example.com
OPERATOR_IMAGE ?= $(REGISTRY)/intel-tdx-dcap-operator:v$(VERSION)
QGS_IMAGE ?= $(REGISTRY)/intel-tdx-qgs:v$(VERSION)

USE_IMAGE_DIGESTS ?= 0
_USE_IMAGE_DIGESTS_FLAG = $(if $(filter 1,$(USE_IMAGE_DIGESTS)),--use-image-digests)

# Generate OLM bundle. Override VERSION, CHANNELS, DEFAULT_CHANNEL, OPERATOR_IMAGE,
# and QGS_IMAGE as needed. Set USE_IMAGE_DIGESTS=1 for release builds to pin images
# to digests and auto-populate spec.relatedImages:
#   make bundle VERSION=0.1.0 REGISTRY=ghcr.io/intel USE_IMAGE_DIGESTS=1
#
# Requires: operator-sdk, kustomize
bundle:
	# Regenerate CSV base from RBAC markers before applying image overrides.
	operator-sdk generate kustomize manifests \
		--input-dir=$(KUSTOMIZE_DIR) \
		--output-dir=$(KUSTOMIZE_DIR) \
		--package=$(PROJECT_NAME)
	# Pin operator image in kustomization (updates images: stanza in kustomization.yaml).
	cd $(KUSTOMIZE_DIR) && kustomize edit set image intel-tdx-dcap-operator=$(OPERATOR_IMAGE)
	# Generate QGS env patch from template.
	sed 's|INTEL_TDX_QGS_IMAGE_PLACEHOLDER|$(QGS_IMAGE)|g' \
		$(KUSTOMIZE_DIR)/patches/qgs-env.yaml.tmpl \
		> $(KUSTOMIZE_DIR)/patches/qgs-env.yaml
	# Build and generate bundle. Use USE_IMAGE_DIGESTS=1 for release builds.
	kustomize build $(KUSTOMIZE_DIR) | operator-sdk generate bundle \
		$(_USE_IMAGE_DIGESTS_FLAG) \
		--version=$(VERSION) \
		--package=$(PROJECT_NAME) \
		--output-dir=$(BUNDLE_DIR) \
		--overwrite \
		--extra-service-accounts intel-tdx-dcap-qgs \
		$(BUNDLE_METADATA_OPTS)
	operator-sdk bundle validate $(BUNDLE_DIR)
