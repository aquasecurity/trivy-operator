![Trivy-operator logo](docs/images/trivy-operator-logo.png)

> Kubernetes-native security toolkit. ([Documentation](https://aquasecurity.github.io/trivy/latest/docs/kubernetes/operator/))

[![GitHub Release][release-img]][release]
[![Build Action][action-build-img]][action-build]
[![Release snapshot Action][action-release-snapshot-img]][action-release-snapshot]
[![Coverage Status][cov-img]][cov]
[![Go Report Card][report-card-img]][report-card]
[![License][license-img]][license]
[![GitHub All Releases][github-all-releases-img]][release]
![Docker Pulls Trivy-operator][docker-pulls-trivy-operator]

# Introduction

There are lots of security tools in the cloud native world, created by Aqua and by others, for identifying and informing
users about security issues in Kubernetes workloads and infrastructure components. However powerful and useful they
might be, they tend to sit alongside Kubernetes, with each new product requiring users to learn a separate set of
commands and installation steps in order to operate them and find critical security information.

Trivy-Operator leverage the trivy security tools by incorporating it outputs into Kubernetes CRDs
(Custom Resource Definitions) and from there, making security reports accessible through the Kubernetes API. This way
users can find and view the risks that relate to different resources in what we call a Kubernetes-native way.

Trivy-Operator provides:

- Automated vulnerability scanning for Kubernetes workloads.
- Automated configuration audits for Kubernetes resources with predefined rules or custom Open Policy Agent (OPA) policies.
- [Custom Resource Definitions] and a [Go module] to work with and integrate a range of security scanners.
- The [Lens Extension] that make security reports available through familiar Kubernetes interfaces.

<p align="center">
<img src="docs/images/trivy-operator-overview.png" alt="Trivy-operator Overview"/>
</p>

Trivy-Operator can be used:

- As a [Kubernetes operator] to automatically update security reports in response to workload and other changes on a
  Kubernetes cluster - for example, initiating a vulnerability and misconfiguration scan when a new Pod is started.

# Status

Although we are trying to keep new releases backward compatible with previous versions, this project is still incubating,
and some APIs and [Custom Resource Definitions] may change.

# Documentation

The official [Documentation] provides detailed installation, configuration, troubleshooting, and quick start guides.

You can install the Trivy-operator Operator with [Static YAML Manifests] and follow the [Getting Started][getting-started-operator]
guide to see how vulnerability and configuration audit reports are generated automatically.


# Contributing

At this early stage we would love your feedback on the overall concept of Trivy-Operator. Over time, we'd love to see
contributions integrating different security tools so that users can access security information in standard,
Kubernetes-native ways.

* See [Contributing] for information about setting up your development environment, and the contribution workflow that
  we expect.

---
Trivy-Operator is an [Aqua Security](https://aquasec.com) open source project.  
Learn about our [Open Source Work and Portfolio].  
Join the community, and talk to us about any matter in [GitHub Discussions] or [Slack].

[release-img]: https://img.shields.io/github/release/aquasecurity/trivy-operator.svg?logo=github
[release]: https://github.com/aquasecurity/trivy-operator/releases
[action-build-img]: https://github.com/aquasecurity/trivy-operator/actions/workflows/build.yaml/badge.svg
[action-build]: https://github.com/aquasecurity/trivy-operator/actions/workflows/build.yaml
[action-release-snapshot-img]: https://github.com/aquasecurity/trivy-operator/actions/workflows/release-snapshot.yaml/badge.svg
[action-release-snapshot]: https://github.com/aquasecurity/trivy-operator/actions/workflows/release-snapshot.yaml
[cov-img]: https://codecov.io/github/aquasecurity/trivy-operator/branch/main/graph/badge.svg
[cov]: https://codecov.io/github/aquasecurity/trivy-operator
[report-card-img]: https://goreportcard.com/badge/github.com/aquasecurity/trivy-operator
[report-card]: https://goreportcard.com/report/github.com/aquasecurity/trivy-operator
[license-img]: https://img.shields.io/github/license/aquasecurity/trivy-operator.svg
[license]: https://github.com/aquasecurity/trivy-operator/blob/main/LICENSE
[github-all-releases-img]: https://img.shields.io/github/downloads/aquasecurity/trivy-operator/total?logo=github
[docker-pulls-trivy-operator]: https://img.shields.io/docker/pulls/aquasec/trivy-operator?logo=docker&label=docker%20pulls%20%2F%20trivy%20operator
[Contributing]: CONTRIBUTING.md
[GitHub Discussions]: https://github.com/aquasecurity/trivy-operator/discussions
[Slack]: https://slack.aquasec.com/
[Open Source Work and Portfolio]: https://www.aquasec.com/products/open-source-projects/

[Custom Resource Definitions]: https://github.com/aquasecurity/trivy-operator/tree/main/deploy/crd
[Go module]: https://pkg.go.dev/github.com/aquasecurity/trivy-operator/pkg
[Documentation]: https://aquasecurity.github.io/trivy
[Static YAML Manifests]: https://aquasecurity.github.io/trivy/latest/docs/kubernetes/operator/installation/kubectl/
[getting-started-operator]: https://aquasecurity.github.io/trivy/latest/docs/kubernetes/operator/getting-started/
[Kubernetes operator]: https://aquasecurity.github.io/trivy/latest/docs/kubernetes/operator/

[Lens Extension]: https://github.com/aquasecurity/trivy-operator-lens-extension
[kubectl]: https://kubernetes.io/docs/reference/kubectl
