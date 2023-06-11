# Contributing

These guidelines will help you get started with the Trivy-operator project.

## Table of Contents

- [Contribution Workflow](#contribution-workflow)
  - [Issues and Discussions](#issues-and-discussions)
  - [Pull Requests](#pull-requests)
- [Set up your Development Environment](#set-up-your-development-environment)
- [Build Binaries](#build-binaries)
- [Testing](#testing)
  - [Run Tests](#run-tests)
  - [Run Integration Tests](#run-integration-tests)
  - [Cove Coverage](#code-coverage)
- [Custom Resource Definitions](#custom-resource-definitions)
  - [Generating code and manifests](#generating-code-and-manifests)
- [Test Trivy Operator](#test-trivy-operator)
  - [In Cluster](#in-cluster)
  - [Out of Cluster](#out-of-cluster)
- [Update Static YAML Manifests](#update-static-yaml-manifests)
- [Operator Lifecycle Manager (OLM)](#operator-lifecycle-manager-olm)
  - [Install OLM](#install-olm)
  - [Build the Catalog Image](#build-the-catalog-image)
  - [Register the Catalog Image](#register-the-catalog-image)

## Contribution Workflow

### Issues and Discussions

- Feel free to open issues for any reason as long as you make it clear what this issue is about: bug/feature/proposal/comment.
- For questions and general discussions, please do not open an issue, and instead create a discussion in the "Discussions" tab.
- Please spend a minimal amount of time giving due diligence to existing issues or discussions. Your topic might be a duplicate. If it is, please add your comment to the existing one.
- Please give your issue or discussion a meaningful title that will be clear for future users.
- The issue should clearly explain the reason for opening, the proposal if you have any, and any relevant technical information.
- For technical questions, please explain in detail what you were trying to do, provide an error message if applicable, and your versions of Trivy-Operator and your environment.

### Pull Requests

- Every Pull Request should have an associated Issue unless it is a trivial fix.
- Your PR is more likely to be accepted if it focuses on just one change.
- Describe what the PR does. There's no convention enforced, but please try to be concise and descriptive. Treat the PR description as a commit message. Titles that start with "fix"/"add"/"improve"/"remove" are good examples.
- There's no need to add or tag reviewers, if your PR is left unattended for too long, you can add a comment to bring it up to attention, optionally "@" mention one of the maintainers that was involved with the issue.
- If a reviewer commented on your code or asked for changes, please remember to mark the discussion as resolved after you address it and re-request a review.
- When addressing comments, try to fix each suggestion in a separate commit.
- Tests are not required at this point as Trivy-Operator is evolving fast, but if you can include tests that will be appreciated.

#### Conventional Commits

It is not that strict, but we use the [Conventional commits](https://www.conventionalcommits.org) in this repository.
Each commit message doesn't have to follow conventions as long as it is clear and descriptive since it will be squashed and merged.

## Set up your Development Environment

1. Install Go

   The project requires [Go 1.19][go-download] or later. We also assume that you're familiar with
   Go's [GOPATH workspace][go-code] convention, and have the appropriate environment variables set.
2. Get the source code:

   ```
   git clone git@github.com:aquasecurity/trivy-operator.git
   cd trivy-operator
   ```

3. Access to a Kubernetes cluster. We assume that you're using a [KIND][kind] cluster. To create a single-node KIND
   cluster, run:

   ```
   kind create cluster
   ```

Note: Some of our tests performs integration testing by starting a local
control plane using
[envtest](https://pkg.go.dev/sigs.k8s.io/controller-runtime/pkg/envtest).
If you only run test using the Makefile
(`m̀ake test`), no additional installation is required. But if you want to
run some of these integration tests using `go test` or from your IDE, you'll
have to
[install kubebuiler-tools](https://book.kubebuilder.io/reference/envtest.html#installation).

## Build Binaries

| Binary               | Image                                          | Description                                                   |
|----------------------|------------------------------------------------|---------------------------------------------------------------|
| `trivy-operator`     | `ghcr.io/aquasecurity/trivy-operator:dev`         | Trivy Operator                                                |

To build all Trivy-operator binary, run:

```
make
```

This uses the `go build` command and builds binaries in the `./bin` directory.

To build all Trivy-operator binary into Docker images, run:

```
make docker-build
```

To load Docker images into your KIND cluster, run:

```
kind load docker-image aquasecurity/trivy-operator:dev
```

## Testing

We generally require tests to be added for all, but the most trivial of changes. However, unit tests alone don't
provide guarantees about the behaviour of Trivy-operator. To verify that each Go module correctly interacts with its
collaborators, more coarse grained integration tests might be required.

### Run unit Tests

To run all tests with code coverage enabled, run:

```
make test
```

To open the test coverage report in your web browser, run:

```
go tool cover -html=coverage.txt
```

### Run operator envtest

The operator envtest spin us partial k8s components (api-server, etcd) and test controllers for reousce, workload, ttl, rbac and more

```
make envtest
```

### Run Integration Tests

The integration tests assumes that you have a working kubernetes cluster (e.g KIND cluster) and `KUBECONFIG` environment
variable is pointing to that cluster configuration file. For example:

```shell
export KUBECONFIG=~/.kube/config
```

To open the test coverage report in your web browser, run:

```shell
go tool cover -html=itest/trivy-operator/coverage.txt
```

To run the integration tests for Trivy-operator Operator and view the coverage report, first do the
[pre-requisite steps](#set-up-your-development-environment), and then run:

```
OPERATOR_NAMESPACE=trivy-system \
  OPERATOR_TARGET_NAMESPACES=default \
  OPERATOR_LOG_DEV_MODE=true \
  make itests-trivy-operator
go tool cover -html=itest/trivy-operator/coverage.txt
```

### Run  End to End Tests

The end 2 end tests assumes that you have a working kubernetes cluster (e.g KIND cluster) and `KUBECONFIG` environment
variable is pointing to that cluster configuration file. For example:

```shell
export KUBECONFIG=~/.kube/config
```

- install kuttl via krew [Install Guide](https://kuttl.dev/docs/cli.html)

```shell
kubectl krew install kuttl
```

- Run cluster infra assessment end to end test via node collector

```shell
kubectl kuttl test --start-kind=false  --config tests/config/node-collector.yaml
```

- Run vulnerability report generation via running trivy with image mode

```shell
kubectl kuttl test --start-kind=false  --config tests/config/image-mode.yaml
```

- Run vulnerability report generation via running trivy with filesystem mode

```shell
kubectl kuttl test --start-kind=false  --config tests/config/fs-mode.yaml
```

- Run vulnerability report generation via running trivy with client/server mode

```shell
kubectl kuttl test --start-kind=false  --config tests/config/client-server.yaml
```

### Code Coverage

In the CI workflow, after running all tests, we do upload code coverage reports to [Codecov][codecov]. Codecov will
merge the reports automatically while maintaining the original upload context as explained
[here][codecov-merging-reports].

## Custom Resource Definitions

### Generating code and manifests

This project uses [`controller-gen`](https://book.kubebuilder.io/reference/controller-gen.html)
to generate code and Kubernetes manifests from source-code and code markers.
We currently generate:

- Custom Resource Definitions (CRD) for CRDs defined in trivy-operator
- ClusterRole that must be bound to the trivy-operator serviceaccount to allow it to function
- Mandatory DeepCopy functions for a Go struct representing a CRD

This means that you should not try to modify any of these files directly, but instead change
the code and code markers. Our Makefile contains a target to ensure that all generated files
are up-to-date: So after doing modifications in code, affecting CRDs/ClusterRole, you should
run `make generate-all` to regenerate everything.

Our CI will verify that all generated is up-to-date by running `make verify-generated`.

Any change to the CRD structs, including nested structs, will probably modify the CRD.
This is also true for Go docs, as field/type doc becomes descriptions in CRDs.

When it comes to code markers added to the code, run `controller-gen -h` for detailed
reference (add more `h`'s to the command to get more details)
or the [markers documentation](https://book.kubebuilder.io/reference/markers.html) for
an overview.

We are trying to place the [RBAC markers](https://book.kubebuilder.io/reference/markers/rbac.html)
close to the code that drives the requirement for permissions. This could lead to the same,
or similar, RBAC markers multiple places in the code. This how we want it to be, since it will
allow us to track RBAC changes to code changes. Any permission granted multiple times by markers
will be deduplicated by controller-gen.

## Test Trivy Operator

You can deploy the operator in the `trivy-system` namespace and configure it to watch the `default` namespace.
In OLM terms such install mode is called *SingleNamespace*. The *SingleNamespace* mode is good to get started with a
basic development workflow. For other install modes see [Operator Multitenancy with OperatorGroups][olm-operator-groups].

### In cluster

1. Build the operator binary into the Docker image and load it from your host into KIND cluster nodes:

   ```
   make docker-build-trivy-operator && kind load docker-image aquasecurity/trivy-operator:dev
   ```

2. Create the `trivy-operator` Deployment in the `trivy-system` namespace to run the operator's container:

   ```
   kubectl create -k deploy/static
   ```

You can uninstall the operator with:

```
kubectl delete -k deploy/static
```

### Out of cluster

1. Deploy the operator in cluster:

   ```
   kubectl apply -f deploy/static/trivy-operator.yaml
   ```

2. Scale the operator down to zero replicas:

   ```
   kubectl scale deployment trivy-operator \
     -n trivy-system \
     --replicas 0
   ```

3. Delete pending scan jobs with:

   ```
   kubectl delete jobs -n trivy-system --all
   ```

4. Run the main method of the operator program:

   ```
   OPERATOR_NAMESPACE=trivy-system \
     OPERATOR_TARGET_NAMESPACES=default \
     OPERATOR_LOG_DEV_MODE=true \
     OPERATOR_VULNERABILITY_SCANNER_ENABLED=true \
     OPERATOR_VULNERABILITY_SCANNER_SCAN_ONLY_CURRENT_REVISIONS=false \
     OPERATOR_CONFIG_AUDIT_SCANNER_ENABLED=true \
     OPERATOR_RBAC_ASSESSMENT_SCANNER_ENABLED=true \
     OPERATOR_CONFIG_AUDIT_SCANNER_SCAN_ONLY_CURRENT_REVISIONS=false \
     OPERATOR_VULNERABILITY_SCANNER_REPORT_TTL="" \
     OPERATOR_BATCH_DELETE_LIMIT=3 \
     OPERATOR_BATCH_DELETE_DELAY="30s" \
     go run cmd/trivy-operator/main.go
   ```

You can uninstall the operator with:

```
kubectl delete -f deploy/static/trivy-operator.yaml
```

## Update Static YAML Manifests

We consider the Helm chart to be the master for deploying trivy-operator.
Since some prefer to not use Helm, we also provide static resources to
install the operator.

To avoid maintaining resources in multiple places, we have a created a script
to (re)generate the static resources from the Helm chart.

So if modifying the operator resources, please do so by modifying the Helm
chart, then run `make manifests` to ensure the static
resources are up-to-date.

## Update helm docs

We consider the Helm chart to be the master for deploying trivy-operator.
Since some prefer to not use Helm, we also provide helm config documentation to
install the operator.

So if modifying the operator helm params, please do so by modifying the Helm
chart, then run `make generate-helm-docs` to ensure the helm docs are up-to-date.

## Operator Lifecycle Manager (OLM)

### Install OLM

To install [Operator Lifecycle Manager] (OLM) run:

```
kubectl apply -f https://github.com/operator-framework/operator-lifecycle-manager/releases/download/v0.20.0/crds.yaml
kubectl apply -f https://github.com/operator-framework/operator-lifecycle-manager/releases/download/v0.20.0/olm.yaml
```

or

```
curl -L https://github.com/operator-framework/operator-lifecycle-manager/releases/download/v0.20.3/install.sh -o install.sh
chmod +x install.sh
./install.sh v0.20.0
```

### Build the Catalog Image

The Trivy Operator metadata is formatted in *packagemanifest* layout, so you need to place it in the directory
structure of the [community-operators] repository.

```
git clone git@github.com:k8s-operatorhub/community-operators.git
cd community-operators
```

Build the catalog image for OLM containing just Trivy Operator with a Dockerfile like this:

```
cat << EOF > trivy-operator.Dockerfile
FROM quay.io/operator-framework/upstream-registry-builder as builder

COPY operators/trivy-operator manifests
RUN /bin/initializer -o ./bundles.db

FROM scratch
COPY --from=builder /etc/nsswitch.conf /etc/nsswitch.conf
COPY --from=builder /bundles.db /bundles.db
COPY --from=builder /bin/registry-server /registry-server
COPY --from=builder /bin/grpc_health_probe /bin/grpc_health_probe
EXPOSE 50051
ENTRYPOINT ["/registry-server"]
CMD ["--database", "bundles.db"]
EOF
```

Place the `trivy-operator.Dockerfile` in the top-level directory of your cloned copy of the [community-operators] repository,
build it and push to a registry from where you can download it to your Kubernetes cluster:

```
docker image build -f trivy-operator.Dockerfile -t docker.io/<your account>/trivy-operator-catalog:dev .
docker image push docker.io/<your account>/trivy-operator-catalog:dev
```

### Register the Catalog Image

Create a CatalogSource instance in the `olm` namespace to reference in the Operator catalog image that contains the
Trivy Operator:

```
cat << EOF | kubectl apply -f -
apiVersion: operators.coreos.com/v1alpha1
kind: CatalogSource
metadata:
  name: trivy-operator-catalog
  namespace: olm
spec:
  publisher: trivy-operator Maintainers
  displayName: trivy-operator Catalog
  sourceType: grpc
  image: docker.io/<your account>/trivy-operator-catalog:dev
EOF
```

You can delete the default catalog that OLM ships with to avoid duplicate entries:

```
kubectl delete catalogsource operatorhubio-catalog -n olm
```

Inspect the list of loaded package manifests on the system with the following command to filter for the Trivy Operator:

```console
$ kubectl get packagemanifests
NAME                 CATALOG             AGE
trivy-operator   trivy-operator Catalog   97s
```

If the Trivy Operator appears in this list, the catalog was successfully parsed and it is now available to install.
Follow the installation instructions for [OLM][trivy-operator-install-olm]. Make sure that the Subscription's `spec.source`
property refers to the `trivy-operator-catalog` source instead of `operatorhubio-catalog`.

You can find more details about testing Operators with Operator Framework [here][olm-testing-operators].

[go-download]: https://golang.org/dl/
[go-code]: https://golang.org/doc/code.html
[kind]: https://github.com/kubernetes-sigs/kind
[codecov]: https://codecov.io/
[codecov-merging-reports]: https://docs.codecov.io/docs/merging-reports/
[Operator Lifecycle Manager]: https://github.com/operator-framework/operator-lifecycle-manager
[community-operators]: https://github.com/k8s-operatorhub/community-operators
[olm-operator-groups]: https://github.com/operator-framework/operator-lifecycle-manager/blob/master/doc/design/operatorgroups.md
[trivy-operator-install-olm]: https://aquasecurity.github.io/trivy-operator/latest/operator/installation/olm
[olm-testing-operators]: https://github.com/operator-framework/community-operators/blob/master/docs/testing-operators.md
