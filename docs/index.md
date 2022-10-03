Trivy has a native [Kubernetes Operator](operator) which continuously scans your Kubernetes cluster for security issues, and generates security reports as Kubernetes [Custom Resources](crd). It does it by watching Kubernetes for state changes and automatically triggering scans in response to changes, for example initiating a vulnerability scan when a new Pod is created.

> Trivy Operator is based on existing Aqua OSS project - [Starboard], and shares some of the design, principles and code with it. Existing content that relates to Starboard Operator might also be relevant for Trivy Operator. To learn more about the transition from Starboard to Trivy, see the [announcement discussion](https://github.com/aquasecurity/starboard/discussions/1173).

<figure>
  <img src="./images/operator/trivy-operator-workloads.png" />
  <figcaption>Workload reconcilers discover K8s controllers, manage scan jobs, and create VulnerabilityReport and ConfigAuditReport objects.</figcaption>
</figure>
