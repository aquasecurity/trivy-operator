# Contributing

These guidelines will help you get started with the Starboard project.

## Table of Contents

- [Contribution Workflow](#contribution-workflow)
  - [Issues and Discussions](#issues-and-discussions)
  - [Pull Requests](#pull-requests)
- [Set up your Development Environment](#set-up-your-development-environment)
- [Build Binaries](#build-binaries)
- [Run Tests](#run-tests)
  - [Run Unit Tests](#run-unit-tests)
  - [Run Integration Tests](#run-integration-tests)
  - [Cove Coverage](#code-coverage)
- [Custom Resource Definitions](#custom-resource-definitions)
  - [Generate Code](#generate-code)
- [Test Starboard Operator](#test-starboard-operator)
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

   The project requires [Go 1.17][go-download] or later. We also assume that you're familiar with
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

## Build Binaries

| Binary               | Image                                          | Description                                                   |
|----------------------|------------------------------------------------|---------------------------------------------------------------|
| `starboard`          | `docker.io/aquasec/starboard:dev`              | Starboard command-line interface                              |
| `trivy-operator`     | `docker.io/aquasec/trivy-operator:dev`         | Trivy Operator                                                |
| `trivy-scanner-aqua` | `docker.io/aquasec/starboard-scanner-aqua:dev` | Starboard plugin to integrate with Aqua vulnerability scanner |

To build all Starboard binaries, run:

```
make
```

This uses the `go build` command and builds binaries in the `./bin` directory.

To build all Starboard binaries into Docker images, run:

```
make docker-build
```

To load Docker images into your KIND cluster, run:

```
kind load docker-image aquasec/starboard:dev
kind load docker-image aquasec/trivy-operator:dev
kind load docker-image aquasec/starboard-scanner-aqua:dev
```

## Run Tests

We generally require tests to be added for all, but the most trivial of changes. However, unit tests alone don't
provide guarantees about the behaviour of Starboard. To verify that each Go module correctly interacts with its
collaborators, more coarse grained integration tests might be required.

### Run Unit Tests

To run all unit tests with code coverage enabled, run:

```
make unit-tests
```

To open the test coverage report in your web browser, run:

```
go tool cover -html=coverage.txt
```

### Run Integration Tests

The integration tests assumes that you have a working kubernetes cluster (e.g KIND cluster) and `KUBECONFIG` environment
variable is pointing to that cluster configuration file. For example:

```
export KUBECONFIG=~/.kube/config
```

There are separate integration tests for Starboard CLI and for Trivy-Operator Operator. The tests may leave the cluster in a
dirty state, so running one test after the other may cause spurious failures.

To run the integration tests for Starboard CLI with code coverage enabled, run:

```
make itests-starboard
```

To open the test coverage report in your web browser, run:

```
go tool cover -html=itest/starboard/coverage.txt
```

To run the integration tests for Starboard Operator and view the coverage report, first do the
[prerequisite steps](#prerequisites), and then run:

```
OPERATOR_NAMESPACE=starboard-system \
  OPERATOR_TARGET_NAMESPACES=default \
  OPERATOR_LOG_DEV_MODE=true \
  make itests-starboard-operator
go tool cover -html=itest/starboard-operator/coverage.txt
```

### Code Coverage

In the CI workflow, after running all tests, we do upload code coverage reports to [Codecov][codecov]. Codecov will
merge the reports automatically while maintaining the original upload context as explained
[here][codecov-merging-reports].

## Custom Resource Definitions

### Generate Code

Code generators are used a lot in the implementation of native Kubernetes resources, and we're using the very same
generators here for custom security resources. This project follows the patterns of
[k8s.io/sample-controller][k8s-sample-controller], which is a blueprint for many controllers built in Kubernetes itself.

The code generation starts with:

```
go mod vendor
export GOPATH="$(go env GOPATH)"
./hack/update-codegen.sh
```

In addition, there is a second script called `./hack/verify-codegen.sh`. This script calls the
`./hack/update-codegen.sh` script and checks whether anything changed, and then it terminates with a nonzero return
code if any of the generated files is not up-to-date. We're running it as a step in the CI workflow.

## Test Starboard Operator

You can deploy the operator in the `starboard-system` namespace and configure it to watch the `default` namespace.
In OLM terms such install mode is called *SingleNamespace*. The *SingleNamespace* mode is good to get started with a
basic development workflow. For other install modes see [Operator Multitenancy with OperatorGroups][olm-operator-groups].

### In cluster

1. Build the operator binary into the Docker image and load it from your host into KIND cluster nodes:
   ```
   make docker-build-starboard-operator && kind load docker-image aquasec/starboard-operator:dev
   ```
2. Create the `starboard-operator` Deployment in the `starboard-system` namespace to run the operator's container:
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
   kubectl apply -f deploy/static/starboard.yaml
   ```
2. Scale the operator down to zero replicas:
   ```
   kubectl scale deployment starboard-operator \
     -n starboard-system \
     --replicas 0
   ```
3. Delete pending scan jobs with:
   ```
   kubectl delete jobs -n starboard-system --all
   ```
4. Run the main method of the operator program:
   ```
   OPERATOR_NAMESPACE=starboard-system \
     OPERATOR_TARGET_NAMESPACES=default \
     OPERATOR_LOG_DEV_MODE=true \
     OPERATOR_CIS_KUBERNETES_BENCHMARK_ENABLED=true \
     OPERATOR_VULNERABILITY_SCANNER_ENABLED=true \
     OPERATOR_VULNERABILITY_SCANNER_SCAN_ONLY_CURRENT_REVISIONS=false \
     OPERATOR_CONFIG_AUDIT_SCANNER_ENABLED=false \
     OPERATOR_CONFIG_AUDIT_SCANNER_SCAN_ONLY_CURRENT_REVISIONS=false \
     OPERATOR_CONFIG_AUDIT_SCANNER_BUILTIN=true \
     OPERATOR_VULNERABILITY_SCANNER_REPORT_TTL="" \
     OPERATOR_BATCH_DELETE_LIMIT=3 \
     OPERATOR_BATCH_DELETE_DELAY="30s" \
     go run cmd/starboard-operator/main.go
   ```

You can uninstall the operator with:

```
kubectl delete -f deploy/static/starboard.yaml
```

## Update Static YAML Manifests

```
mkdir -p $TMPDIR/starboard-helm-template
```

```
helm template starboard-operator ./deploy/helm \
  --namespace starboard-system --create-namespace \
  --set="targetNamespaces=default" \
  --set="managedBy=kubectl" \
  --output-dir=$TMPDIR/starboard-helm-template
```

```
cp $TMPDIR/starboard-helm-template/starboard-operator/templates/rbac.yaml deploy/static/02-starboard-operator.rbac.yaml
cp $TMPDIR/starboard-helm-template/starboard-operator/templates/config.yaml deploy/static/03-starboard-operator.config.yaml
cp $TMPDIR/starboard-helm-template/starboard-operator/templates/deployment.yaml deploy/static/04-starboard-operator.deployment.yaml
```

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

The Starboard Operator metadata is formatted in *packagemanifest* layout, so you need to place it in the directory
structure of the [community-operators] repository.

```
git clone git@github.com:k8s-operatorhub/community-operators.git
cd community-operators
```

Build the catalog image for OLM containing just Starboard Operator with a Dockerfile like this:

```
cat << EOF > starboard.Dockerfile
FROM quay.io/operator-framework/upstream-registry-builder as builder

COPY operators/starboard-operator manifests
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

Place the `starboard.Dockerfile` in the top-level directory of your cloned copy of the [community-operators] repository,
build it and push to a registry from where you can download it to your Kubernetes cluster:

```
docker image build -f starboard.Dockerfile -t docker.io/<your account>/starboard-catalog:dev .
docker image push docker.io/<your account>/starboard-catalog:dev
```

### Register the Catalog Image

Create a CatalogSource instance in the `olm` namespace to reference in the Operator catalog image that contains the
Starboard Operator:

```
cat << EOF | kubectl apply -f -
apiVersion: operators.coreos.com/v1alpha1
kind: CatalogSource
metadata:
  name: starboard-catalog
  namespace: olm
spec:
  publisher: Starboard Maintainers
  displayName: Starboard Catalog
  sourceType: grpc
  image: docker.io/<your account>/starboard-catalog:dev
EOF
```

You can delete the default catalog that OLM ships with to avoid duplicate entries:

```
kubectl delete catalogsource operatorhubio-catalog -n olm
```

Inspect the list of loaded packagemanifests on the system with the following command to filter for the Starboard Operator:

```console
$ kubectl get packagemanifests
NAME                 CATALOG             AGE
starboard-operator   Starboard Catalog   97s
```

If the Starboard Operator appears in this list, the catalog was successfully parsed and it is now available to install.
Follow the installation instructions for [OLM][starboard-install-olm]. Make sure that the Subscription's `spec.source`
property refers to the `starboard-catalog` source instead of `operatorhubio-catalog`.

You can find more details about testing Operators with Operator Framework [here][olm-testing-operators].

[go-download]: https://golang.org/dl/
[go-code]: https://golang.org/doc/code.html
[kind]: https://github.com/kubernetes-sigs/kind
[codecov]: https://codecov.io/
[codecov-merging-reports]: https://docs.codecov.io/docs/merging-reports/
[Operator Lifecycle Manager]: https://github.com/operator-framework/operator-lifecycle-manager
[community-operators]: https://github.com/k8s-operatorhub/community-operators
[olm-operator-groups]: https://github.com/operator-framework/operator-lifecycle-manager/blob/master/doc/design/operatorgroups.md
[k8s-sample-controller]: https://github.com/kubernetes/sample-controller
[starboard-install-olm]: https://aquasecurity.github.io/starboard/latest/operator/installation/olm
[olm-testing-operators]: https://github.com/operator-framework/community-operators/blob/master/docs/testing-operators.md
