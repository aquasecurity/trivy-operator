# Compliance Reports

!!! warning "EXPERIMENTAL"
    This feature might change without preserving backwards compatibility.

Trivy-operator compliance crds allow you create a specific set of checks into a report. There are hundreds of different checks for many different components and configurations, but sometimes you already know which specific checks you are interested in. Often this would be an industry accepted set of checks such as CIS, or some vendor specific guideline, or your own organization policy that you want to comply with. These are all possible using the flexible compliance infrastructure that's built into Trivy-operator. Compliance reports are defined as simple YAML documents that select checks to include in the report.

The compliance report will be generated every six hours by default.

The compliance report is composed of two parts :

- `spec`: represents the compliance control checks specification, check details, and the mapping to the security scanner

- `status`: represents the compliance control checks results

- `report types` : compliance report can be produced in two formats, summary and detail (all)

Spec can be customized by amending the control checks `report type (summary / all)` , `severity` and `cron` expression (report execution interval).
As an example, let's enter `vi` edit mode and change the `cron` expression.
```shell
kubectl edit compliance
```
Once the report has been generated, you can fetch and review its results section. As an example, let's fetch the compliance status report in JSON format

```shell
kubectl get compliance nsa  -o=jsonpath='{.status}' | jq .
```

## Custom compliance reports

You can create your own custom compliance report. A compliance report is a simple YAML document in the following format:

```yaml
apiVersion: aquasecurity.github.io/v1alpha1
kind: ClusterComplianceReport
metadata:
  creationTimestamp: "2022-12-04T18:25:27Z"
  labels:
    app.kubernetes.io/instance: trivy-operator
    app.kubernetes.io/managed-by: kubectl
    app.kubernetes.io/name: trivy-operator
    app.kubernetes.io/version: 0.8.0
  name: nsa # report unique identifier. this should not container spaces.
spec:
  cron: '* * * * *'
  reportType: summary
  compliance:
    title: nsa # report title. Any one-line title.
    description: NSA, Kubernetes Hardening  # description of the report. Any text.
    version: "1.0"
    controls:
    - checks:
      - id: AVD-KSV-0012 # check ID. Must start with `AVD-` 
      description: Check that container is not running as root   # Description (appears in the report as is). Any text.
      id: "1.0"
      name: Non-root containers # Name for the control (appears in the report as is). Any one-line name.
      severity: MEDIUM  (note that checks severity isn't used)
```

## Built in reports

The following reports are available out of the box:

| Compliance | Name for command | More info
--- | --- | ---
NSA, CISA Kubernetes Hardening Guidance v1.2 | `nsa` | [Link](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF)
CIS Benchmark for Kubernetes v1.23 | `cis` | [Link](https://www.cisecurity.org/benchmark/kubernetes)
Kubernetes pss-restricted | `pss-restricted` | [Link](https://kubernetes.io/docs/concepts/security/pod-security-standards/#restricted)
Kubernetes pss-baseline | `pss-baseline` | [Link](https://kubernetes.io/docs/concepts/security/pod-security-standards/#baseline)
