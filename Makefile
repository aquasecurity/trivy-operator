# Set the default goal
.DEFAULT_GOAL := build
MAKEFLAGS += --no-print-directory

DOCKER ?= docker
KIND ?= kind

export KUBECONFIG ?= ${HOME}/.kube/config

# Active module mode, as we use Go modules to manage dependencies
export GO111MODULE=on
GOPATH=$(shell go env GOPATH)
GOBIN=$(GOPATH)/bin
GINKGO=$(GOBIN)/ginkgo

SOURCES := $(shell find . -name '*.go')

IMAGE_TAG := dev
TRIVY_OPERATOR_IMAGE := aquasec/trivy-operator:$(IMAGE_TAG)
TRIVY_OPERATOR_IMAGE_UBI8 := aquasec/trivy-operator:$(IMAGE_TAG)-ubi8

MKDOCS_IMAGE := aquasec/mkdocs-material:trivy-operator
MKDOCS_PORT := 8000

# ENVTEST_K8S_VERSION refers to the version of kubebuilder assets to be downloaded by envtest binary.
ENVTEST_K8S_VERSION = 1.24.2

.PHONY: all
all: build

.PHONY: build
build: build-trivy-operator

## Builds the trivy-operator binary
build-trivy-operator: $(SOURCES)
	CGO_ENABLED=0 GOOS=linux go build -o ./bin/trivy-operator ./cmd/trivy-operator/main.go

.PHONY: get-ginkgo
## Installs Ginkgo CLI
get-ginkgo:
	@go install github.com/onsi/ginkgo/v2/ginkgo

.PHONY: get-qtc
## Installs quicktemplate compiler
get-qtc:
	@go install github.com/valyala/quicktemplate/qtc

.PHONY: compile-templates
## Converts quicktemplate files (*.qtpl) into Go code
compile-templates: get-qtc
	$(GOBIN)/qtc

.PHONY: test
test: $(SOURCES) generate-all envtest ## Run tests.
	KUBEBUILDER_ASSETS="$(shell $(ENVTEST) use $(ENVTEST_K8S_VERSION) -p path)" \
	go test -v -short -race -timeout 30s -coverprofile=coverage.txt ./...

.PHONY: e2e-test
e2e-test: check-kubeconfig
	kubectl kuttl test

.PHONY: test-all
test-all: test e2e-test

.PHONY: check-kubeconfig
check-kubeconfig:
ifndef KUBECONFIG
	$(error Environment variable KUBECONFIG is not set)
else
	@echo "KUBECONFIG=${KUBECONFIG}"
endif

## Removes build artifacts
clean:
	@rm -r ./bin 2> /dev/null || true
	@rm -r ./dist 2> /dev/null || true

## Builds Docker images for all binaries
docker-build: \
	docker-build-trivy-operator \
	docker-build-trivy-operator-ubi8

## Builds Docker image for trivy-operator
docker-build-trivy-operator: build-trivy-operator
	$(DOCKER) build --no-cache -t $(TRIVY_OPERATOR_IMAGE) -f build/trivy-operator/Dockerfile bin
	
## Builds Docker image for trivy-operator ubi8
docker-build-trivy-operator-ubi8: build-trivy-operator
	$(DOCKER) build --no-cache -f build/trivy-operator/Dockerfile.ubi8 -t $(TRIVY_OPERATOR_IMAGE_UBI8) bin

kind-load-images: \
	docker-build-trivy-operator \
	docker-build-trivy-operator-ubi8
	$(KIND) load docker-image \
		$(TRIVY_OPERATOR_IMAGE) \
		$(TRIVY_OPERATOR_IMAGE_UBI8)

.PHONY: deploy
deploy: manifests kind-load-images
	kubectl apply --server-side -k deploy/static
	# Wait until rollout of operator is finished
	kubectl rollout status -n trivy-system deployment/trivy-operator --timeout=2m \
		|| (kubectl logs -n trivy-system -l=app.kubernetes.io/name=trivy-operator; false)

## Runs MkDocs development server to preview the documentation page
mkdocs-serve:
	$(DOCKER) build -t $(MKDOCS_IMAGE) -f build/mkdocs-material/Dockerfile bin
	$(DOCKER) run --name mkdocs-serve --rm -v $(PWD):/docs -p $(MKDOCS_PORT):8000 $(MKDOCS_IMAGE)

$(GOBIN)/labeler:
	go install github.com/knqyf263/labeler@latest

.PHONY: label
label: $(GOBIN)/labeler
	labeler apply misc/triage/labels.yaml -r aquasecurity/trivy-operator -l 5

## Location to install dependencies to
LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p $(LOCALBIN)

## Tool Binaries
CONTROLLER_GEN ?= $(LOCALBIN)/controller-gen
ENVTEST ?= $(LOCALBIN)/setup-envtest

## Tool Versions
CONTROLLER_TOOLS_VERSION ?= v0.9.2

.PHONY: controller-gen
controller-gen: $(CONTROLLER_GEN) ## Download controller-gen locally if necessary.
$(CONTROLLER_GEN): $(LOCALBIN)
	GOBIN=$(LOCALBIN) go install sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_TOOLS_VERSION)

.PHONY: envtest
envtest: $(ENVTEST) ## Download envtest-setup locally if necessary.
$(ENVTEST): $(LOCALBIN)
	GOBIN=$(LOCALBIN) go install sigs.k8s.io/controller-runtime/tools/setup-envtest@latest

.PHONY: verify-generated
verify-generated: generate-all
	./hack/verify-generated.sh

.PHONY: generate
generate: controller-gen
	$(CONTROLLER_GEN) object:headerFile="hack/boilerplate.go.txt" paths="./pkg/..." +rbac:roleName=trivy-operator output:rbac:artifacts:config=deploy/helm/generated

.PHONY: manifests
manifests: controller-gen
# We must "allow dangerous types" because the API currently includes fields using floating point data types
	$(CONTROLLER_GEN) crd:allowDangerousTypes=true paths="./pkg/apis/..." output:crd:artifacts:config=deploy/crd
	mv deploy/crd/aquasecurity.github.io_clustercompliancedetailreports.yaml deploy/compliance
	mv deploy/crd/aquasecurity.github.io_clustercompliancereports.yaml deploy/compliance
	./hack/update-static.yaml.sh

.PHONY: generate-all
generate-all: generate manifests

.PHONY: \
	clean \
	docker-build \
	docker-build-trivy-operator \
	docker-build-trivy-operator-ubi8 \
	kind-load-images \
	mkdocs-serve
