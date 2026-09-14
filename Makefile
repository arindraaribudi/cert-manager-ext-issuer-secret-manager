.PHONY: codegen manifests generate lint test build docker-build docker-buildx trivy scan audit ci bundle

CONTROLLER_GEN ?= $(shell which controller-gen)
GOLANGCI_LINT ?= $(shell which golangci-lint)
TRIVY         ?= $(shell which trivy)
GOVULNCHECK   ?= govulncheck
IMAGE          ?= cert-manager-ext-issuer-secret-manager
TAG            ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo dev)
PLATFORMS      ?= linux/amd64,linux/arm64
TRIVY_SEVERITY ?= HIGH,CRITICAL

codegen: manifests generate

manifests:
	$(CONTROLLER_GEN) crd:allowDangerousTypes=true,maxDescLen=0 \
	  paths=./api/... \
	  output:crd:dir=config/crd/bases

generate:
	$(CONTROLLER_GEN) object:headerFile="hack/boilerplate.go.txt" paths=./api/...

lint:
	$(GOLANGCI_LINT) run ./...

test:
	go test ./...

build:
	CGO_ENABLED=0 go build -o bin/manager ./cmd

docker-build:
	docker buildx build \
	  --platform=$(PLATFORMS) \
	  --tag $(IMAGE):$(TAG) \
	  --load \
	  .

docker-buildx:
	docker buildx build \
	  --platform=$(PLATFORMS) \
	  --tag $(IMAGE):$(TAG) \
	  --push \
	  .

trivy:
	$(TRIVY) image --severity $(TRIVY_SEVERITY) --no-progress $(IMAGE):$(TAG)

scan: trivy

ci: lint test audit build docker-build trivy

audit:
	$(GOVULNCHECK) ./...

bundle: manifests
	@{ set -- config/crd/bases/*.yaml \
	           config/manager/namespace.yaml \
	           config/rbac/role.yaml \
	           config/manager/serviceaccount.yaml \
	           config/manager/role_binding.yaml \
	           config/manager/deployment.yaml; \
	   while [ $$# -gt 0 ]; do \
	     cat "$$1"; shift; \
	     if [ $$# -gt 0 ]; then printf '\n---\n'; fi; \
	   done; \
	} | sed 's|__IMAGE_TAG__|$(TAG)|g' > config/install.yaml