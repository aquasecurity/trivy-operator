![Trivy-operator logo](docs/images/trivy-operator-logo.png)

> Kubernetes-native security toolkit. ([Documentation](https://aquasecurity.github.io/trivy-operator/latest))

[![GitHub Release][release-img]][release]
[![Build Action][action-build-img]][action-build]
[![Release snapshot Action][action-release-snapshot-img]][action-release-snapshot]
[![Go Report Card][report-card-img]][report-card]
[![License][license-img]][license]
[![GitHub All Releases][github-all-releases-img]][release]
![Docker Pulls Trivy-operator][docker-pulls-trivy-operator]
<a href="https://slack.aquasec.com/?_ga=2.51428586.2119512742.1655808394-1739877964.1641199050">
<img src="https://img.shields.io/static/v1?label=Slack&message=Join+our+Community&color=4a154b&logo=slack">
</a>
[![Artifact Hub](https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/trivy-operator)](https://artifacthub.io/packages/helm/trivy-operator/trivy-operator)

# Introduction

There are lots of security tools in the cloud native world, created by Aqua and by others, for identifying and informing
users about security issues in Kubernetes workloads and infrastructure components. However powerful and useful they
might be, they tend to sit alongside Kubernetes, with each new product requiring users to learn a separate set of
commands and installation steps in order to operate them and find critical security information.

The Trivy-Operator leverages trivy security tools by incorporating their outputs into Kubernetes CRDs
(Custom Resource Definitions) and from there, making security reports accessible through the Kubernetes API. This way
users can find and view the risks that relate to different resources in what we call a Kubernetes-native way.

The Trivy operator automatically updates security reports in response to workload and other changes on a Kubernetes cluster, generating the following reports:

- Vulnerability Scans: Automated vulnerability scanning for Kubernetes workloads.
- ConfigAudit Scans: Automated configuration audits for Kubernetes resources with predefined rules or custom Open Policy Agent (OPA) policies.
- Exposed Secret Scans: Automated secret scans which find and detail the location of exposed Secrets within your cluster.
- RBAC scans: Role Based Access Control scans provide detailed information on the access rights of the different resources installed.
- K8s core component infra assessment scan Kubernetes infra core components (etcd,apiserver,scheduler,controller-manager and etc) setting and configuration.
- k8s outdated api validation - a configaudit check will validate if the resource api has been deprecated and planned for removal 
- Compliance reports
  - NSA, CISA Kubernetes Hardening Guidance v1.1 cybersecurity technical report is produced.
  - CIS Kubernetes Benchmark v1.23 cybersecurity technical report is produced.
  - Kubernetes pss-baseline, Pod Security Standards
  - Kubernetes pss-restricted, Pod Security Standards
- SBOM (software bill of materials genertations) for Kubernetes workloads.

<p align="center">
<img src="docs/images/trivy-operator-overview.png" alt="Trivy-operator Overview"/>
</p>

_Please [star ⭐](https://github.com/aquasecurity/trivy-operator/stargazers) the repo if you want us to continue developing and improving trivy-operator! 😀_


# Status

Although we are trying to keep new releases backward compatible with previous versions, this project is still incubating,
and some APIs and [Custom Resource Definitions] may change.

# Usage

The official [Documentation] provides detailed installation, configuration, troubleshooting, and quick start guides.

You can install the Trivy-operator Operator with [Static YAML Manifests] and follow the [Getting Started][getting-started-operator]
guide to see how vulnerability and configuration audit reports are generated automatically.

# Contributing

At this early stage we would love your feedback on the overall concept of Trivy-Operator. Over time, we'd love to see
contributions integrating different security tools so that users can access security information in standard,
Kubernetes-native ways.

* See [Contributing] for information about setting up your development environment, and the contribution workflow that
  we expect.
* Please ensure that you are following our [Code Of Conduct](https://github.com/aquasecurity/community/blob/main/CODE_OF_CONDUCT.md) during any interaction with the Aqua projects and their community.

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

[Custom Resource Definitions]: https://aquasecurity.github.io/trivy-operator/latest/docs/crds/
[Go module]: https://pkg.go.dev/github.com/aquasecurity/trivy-operator/pkg
[Documentation]: https://aquasecurity.github.io/trivy-operator/latest
[Static YAML Manifests]: https://aquasecurity.github.io/trivy-operator/latest/getting-started/installation/kubectl/
[getting-started-operator]: https://aquasecurity.github.io/trivy-operator/latest/
[Kubernetes operator]: https://aquasecurity.github.io/trivy-operator/latest

[Lens Extension]: https://github.com/aquasecurity/trivy-operator-lens-extension
[kubectl]: https://kubernetes.io/docs/reference/kubectl
