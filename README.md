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

The Trivy Operator leverages [Trivy](https://github.com/aquasecurity/trivy) to continuously scan your Kubernetes cluster for security issues. The scans are summarised in security reports as Kubernetes [Custom Resource Definitions](crd), which become accessible through the Kubernetes API. The Operator does this by watching Kubernetes for state changes and automatically triggering security scans in response. For example, a vulnerability scan is initiated when a new Pod is created.
This way, users can find and view the risks that relate to different resources in a `Kubernetes-native` way.

## In-cluster Security Scans

The Trivy Operator automatically generates and updates security reports. These reports are generated in response to new workload and other changes on a Kubernetes cluster, generating the following reports:

- Vulnerability Scans: Automated vulnerability scanning for Kubernetes workloads, control-plane and node components (api-server, controller-manager, kubelet and etc)
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
- SBOM (Software Bill of Materials genertations) for Kubernetes workloads.

<p align="center">
<img src="docs/images/trivy-operator-overview.png" alt="Trivy-operator Overview"/>
</p>

_Please [star ⭐](https://github.com/aquasecurity/trivy-operator/stargazers) the repo if you want us to continue developing and improving trivy-operator! 😀_

## Usage

The official [Documentation] provides detailed installation, configuration, troubleshooting, and quick start guides.

You can install the Trivy-operator Operator with [Static YAML Manifests] and follow the [Getting Started][getting-started-operator]
guide to see how vulnerability and configuration audit reports are generated automatically.

### Quick Start

The Trivy Operator can be installed easily through the [Helm Chart](https://aquasecurity.github.io/trivy-operator/latest/getting-started/installation/helm/):

Add the Aqua chart repository:

```sh
   helm repo add aqua https://aquasecurity.github.io/helm-charts/
   helm repo update
```

Install the Helm Chart:

```sh
   helm install trivy-operator aqua/trivy-operator \
     --namespace trivy-system \
     --create-namespace \
     --version 0.18.4
```

This will install the Trivy Helm Chart into the `trivy-system` namespace and start triggering the scans.

## Status

Although we are trying to keep new releases backward compatible with previous versions, this project is still incubating,
and some APIs and [Custom Resource Definitions] may change.

## Contributing

At this early stage we would love your feedback on the overall concept of Trivy-Operator. Over time, we'd love to see
contributions integrating different security tools so that users can access security information in standard,
Kubernetes-native ways.

- See [Contributing] for information about setting up your development environment, and the contribution workflow that
  we expect.
- Please ensure that you are following our [Code Of Conduct](https://github.com/aquasecurity/community/blob/main/CODE_OF_CONDUCT.md) during any interaction with the Aqua projects and their community.

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
[Documentation]: https://aquasecurity.github.io/trivy-operator/latest
[Static YAML Manifests]: https://aquasecurity.github.io/trivy-operator/latest/getting-started/installation/kubectl/
[getting-started-operator]: https://aquasecurity.github.io/trivy-operator/latest/

