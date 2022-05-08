# Welcome to {{ config.site_name }}

There are lots of security tools in the cloud native world, created by Aqua and by others, for identifying and informing
users about security issues in Kubernetes workloads and infrastructure components. However powerful and useful they
might be, they tend to sit alongside Kubernetes, with each new product requiring users to learn a separate set of
commands and installation steps in order to operate them and find critical security information.

Trivy-Operator attempts to integrate heterogeneous security tools by incorporating their outputs into Kubernetes CRDs
(Custom Resource Definitions) and from there, making security reports accessible through the Kubernetes API. This way
users can find and view the risks that relate to different resources in what we call a Kubernetes-native way.

Trivy-Operator provides:

- Automated vulnerability scanning for Kubernetes workloads.
- Automated configuration audits for Kubernetes resources with predefined rules or custom Open Policy Agent (OPA) policies.
- Automated infrastructures scanning and compliance checks with CIS Benchmarks published by the Center for Internet Security (CIS).
- Automated compliance report - NSA, CISA Kubernetes Hardening Kubernetes Guidance v1.0
- Penetration test results for a Kubernetes cluster.
- [Custom Resource Definitions] and a [Go module] to work with and integrate a range of security scanners.
- The [Octant Plugin] and the [Lens Extension] that make security reports available through familiar Kubernetes interfaces.

<figure>
  <img src="images/trivy-operator-overview.png" />
  <figcaption>The high-level design diagram of Trivy-Operator toolkit.</figcaption>
</figure>

Trivy-Operator can be used:

- As a [Kubernetes operator] to automatically update security reports in response to workload and other changes on a
  Kubernetes cluster - for example, initiating a vulnerability scan when a new Pod is started or running CIS Benchmarks
  when a new Node is added.
- As a [command][cli], so you can trigger scans and view the risks in a kubectl-compatible way or as part of your CI/CD
  pipeline.

## What's Next?

- Learn how to install the Starboard command [From the Binary Releases](./cli/installation/binary-releases.md) and
  follow the [Getting Started](./cli/getting-started.md) guide to generate your first vulnerability and configuration
  audit reports.
- Install the Starboard Operator with [kubectl](./operator/installation/kubectl.md) and follow the
  [Getting Started](./operator/getting-started.md) guide to see how vulnerability and configuration audit reports are
  generated automatically.
- Read more about the motivations for the project in the [Starboard: The Kubernetes-Native Toolkit for Unifying Security]
  blog.
- See a detailed introduction to Starboard with demos at [KubeCon + CloudNativeCon NA 2020][kubecon-video].
- Join the community, and talk to us about any matter in [GitHub Discussions] or [Slack].

[Custom Resource Definitions]: ./crds/index.md
[cli]: cli/index.md
[Kubernetes operator]: operator/index.md
[Go module]: https://pkg.go.dev/github.com/aquasecurity/starboard@{{ git.tag }}
[Octant Plugin]: ./integrations/octant.md
[Lens Extension]: integrations/lens.md
[kubectl]: https://kubernetes.io/docs/reference/kubectl/
[Trivy-Operator: The Kubernetes-Native Toolkit for Unifying Security]: https://blog.aquasec.com/starboard-kubernetes-tools
[GitHub Discussions]: https://github.com/aquasecurity/starboard/discussions/
[Slack]: https://slack.aquasec.com/
[kubecon-video]: https://www.youtube.com/watch?v=cgcwIY1HVI0
[kube-hunter]: https://github.com/aquasecurity/kube-hunter