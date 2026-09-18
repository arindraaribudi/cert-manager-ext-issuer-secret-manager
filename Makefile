.PHONY: codegen manifests generate lint test build docker-build docker-buildx trivy scan audit ci bundle tools

GO_VERSION          ?= 1.27.1
GOLANGCI_LINT_VERSION ?= v2.13.2
CONTROLLER_GEN_VERSION ?= v0.18.0
TRIVY_VERSION        ?= v0.74.0
GOVULNCHECK_VERSION  ?= v1.1.4

CONTROLLER_GEN ?= $(shell which controller-gen)
GOLANGCI_LINT ?= $(shell which golangci-lint)
TRIVY         ?= $(shell which trivy)
GOVULNCHECK   ?= govulncheck
IMAGE          ?= ghcr.io/arindraaribudi/cert-manager-ext-issuer-secret-manager
TAG            ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo dev)
PLATFORMS      ?= linux/amd64,linux/arm64
TRIVY_SEVERITY ?= HIGH,CRITICAL

tools:
	go install sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_GEN_VERSION)
	go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	curl -sSfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
	  | sh -s -- -b $$(go env GOPATH)/bin $(TRIVY_VERSION)

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
	           config/rbac/cert-manager-approver-role.yaml \
	           config/manager/serviceaccount.yaml \
	           config/manager/role_binding.yaml \
	           config/manager/deployment.yaml; \
	   while [ $$# -gt 0 ]; do \
	     cat "$$1"; shift; \
	     if [ $$# -gt 0 ]; then printf '\n---\n'; fi; \
	   done; \
	} | sed 's|__IMAGE_TAG__|$(TAG)|g' > config/install.yaml