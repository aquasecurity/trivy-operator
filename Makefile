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
STARBOARD_CLI_IMAGE := aquasec/starboard:$(IMAGE_TAG)
TRIVY_OPERATOR_IMAGE := aquasec/trivy-operator:$(IMAGE_TAG)
STARBOARD_SCANNER_AQUA_IMAGE := aquasec/starboard-scanner-aqua:$(IMAGE_TAG)
TRIVY_OPERATOR_IMAGE_UBI8 := aquasec/trivy-operator:$(IMAGE_TAG)-ubi8

MKDOCS_IMAGE := aquasec/mkdocs-material:trivy-operator
MKDOCS_PORT := 8000

.PHONY: all
all: build

.PHONY: build
build: build-starboard-cli build-trivy-operator build-starboard-scanner-aqua

## Builds the trivy-operator binary
build-starboard-cli: $(SOURCES)
	CGO_ENABLED=0 go build -o ./bin/starboard ./cmd/starboard/main.go

## Builds the trivy-operator binary
build-trivy-operator: $(SOURCES)
	CGO_ENABLED=0 GOOS=linux go build -o ./bin/trivy-operator ./cmd/trivy-operator/main.go

## Builds the scanner-aqua binary
build-starboard-scanner-aqua: $(SOURCES)
	CGO_ENABLED=0 GOOS=linux go build -o ./bin/starboard-scanner-aqua ./cmd/scanner-aqua/main.go

.PHONY: get-ginkgo
## Installs Ginkgo CLI
get-ginkgo:
	@go install github.com/onsi/ginkgo/ginkgo

.PHONY: get-qtc
## Installs quicktemplate compiler
get-qtc:
	@go install github.com/valyala/quicktemplate/qtc

.PHONY: compile-templates
## Converts quicktemplate files (*.qtpl) into Go code
compile-templates: get-qtc
	$(GOBIN)/qtc

.PHONY: test
## Runs both unit and integration tests
test: unit-tests itests-starboard itests-trivy-operator

.PHONY: unit-tests
## Runs unit tests with code coverage enabled
unit-tests: $(SOURCES)
	go test -v -short -race -timeout 30s -coverprofile=coverage.txt ./...

.PHONY: itests-starboard
## Runs integration tests for Starboard CLI with code coverage enabled
itests-starboard: check-kubeconfig get-ginkgo
	@$(GINKGO) \
	-coverprofile=coverage.txt \
	-coverpkg=github.com/aquasecurity/starboard/pkg/cmd,\
	github.com/aquasecurity/starboard/pkg/plugin,\
	github.com/aquasecurity/starboard/pkg/kube,\
	github.com/aquasecurity/starboard/pkg/kubebench,\
	github.com/aquasecurity/starboard/pkg/kubehunter,\
	github.com/aquasecurity/starboard/pkg/plugin/trivy,\
	github.com/aquasecurity/starboard/pkg/plugin/polaris,\
	github.com/aquasecurity/starboard/pkg/plugin/conftest,\
	github.com/aquasecurity/starboard/pkg/configauditreport,\
	github.com/aquasecurity/starboard/pkg/vulnerabilityreport \
	./itest/starboard

.PHONY: itests-trivy-operator
## Runs integration tests for Starboard Operator with code coverage enabled
itests-trivy-operator: check-kubeconfig get-ginkgo
	@$(GINKGO) \
	-coverprofile=coverage.txt \
	-coverpkg=github.com/aquasecurity/starboard/pkg/operator,\
	github.com/aquasecurity/starboard/pkg/operator/predicate,\
	github.com/aquasecurity/starboard/pkg/operator/controller,\
	github.com/aquasecurity/starboard/pkg/plugin,\
	github.com/aquasecurity/starboard/pkg/plugin/trivy,\
	github.com/aquasecurity/starboard/pkg/plugin/polaris,\
	github.com/aquasecurity/starboard/pkg/plugin/conftest,\
	github.com/aquasecurity/starboard/pkg/configauditreport,\
	github.com/aquasecurity/starboard/pkg/vulnerabilityreport,\
	github.com/aquasecurity/starboard/pkg/kubebench \
	./itest/trivy-operator

.PHONY: integration-operator-conftest
integration-operator-conftest: check-kubeconfig get-ginkgo
	@$(GINKGO) \
	-coverprofile=coverage.txt \
	-coverpkg=github.com/aquasecurity/starboard/pkg/operator,\
	github.com/aquasecurity/starboard/pkg/operator/predicate,\
	github.com/aquasecurity/starboard/pkg/operator/controller,\
	github.com/aquasecurity/starboard/pkg/plugin,\
	github.com/aquasecurity/starboard/pkg/plugin/conftest,\
	github.com/aquasecurity/starboard/pkg/configauditreport \
	./itest/trivy-operator/configauditreport/conftest

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
	docker-build-starboard-cli \
	docker-build-trivy-operator \
	docker-build-trivy-operator-ubi8 \
	docker-build-starboard-scanner-aqua

## Builds Docker image for Starboard CLI
docker-build-starboard-cli: build-starboard-cli
	$(DOCKER) build --no-cache -t $(STARBOARD_CLI_IMAGE) -f build/starboard/Dockerfile bin

## Builds Docker image for Starboard operator
docker-build-trivy-operator: build-trivy-operator
	$(DOCKER) build --no-cache -t $(TRIVY_OPERATOR_IMAGE) -f build/trivy-operator/Dockerfile bin
	
## Builds Docker image for Starboard operator ubi8
docker-build-trivy-operator-ubi8: build-trivy-operator
	$(DOCKER) build --no-cache -f build/trivy-operator/Dockerfile.ubi8 -t $(TRIVY_OPERATOR_IMAGE_UBI8) bin

## Builds Docker image for Aqua scanner
docker-build-starboard-scanner-aqua: build-starboard-scanner-aqua
	$(DOCKER) build --no-cache -t $(STARBOARD_SCANNER_AQUA_IMAGE) -f build/scanner-aqua/Dockerfile bin

kind-load-images: \
	docker-build-trivy-operator \
	docker-build-trivy-operator-ubi8
	$(KIND) load docker-image \
		$(TRIVY_OPERATOR_IMAGE) \
		$(TRIVY_OPERATOR_IMAGE_UBI8)

## Runs MkDocs development server to preview the documentation page
mkdocs-serve:
	$(DOCKER) build -t $(MKDOCS_IMAGE) -f build/mkdocs-material/Dockerfile bin
	$(DOCKER) run --name mkdocs-serve --rm -v $(PWD):/docs -p $(MKDOCS_PORT):8000 $(MKDOCS_IMAGE)

.PHONY: \
	clean \
	docker-build \
	docker-build-starboard-cli \
	docker-build-trivy-operator \
	docker-build-trivy-operator-ubi8 \
	docker-build-starboard-scanner-aqua \
	kind-load-images \
	mkdocs-serve
