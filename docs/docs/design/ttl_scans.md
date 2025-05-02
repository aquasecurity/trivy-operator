# TTL scans

## Summary

Add an option to automatically delete old security reports. In this first version, focus on vulnerability reports, with potential future support for other reports as well.

## Motivation

In [1009](https://github.com/aquasecurity/trivy-operator/issues/1009) we discuss the need to run nightly vulnerability scans of CVEs. This ensures long-running pods receive up-to-date reports.

## Proposal

Add an environment variable, `OPERATOR_SCANNER_REPORT_TTL=12h30m0s`, or configure it through Helm values using `operator.scannerReportTTL`.

This environment variable or value will add an annotation to the generated VulnerabilityReport, indicating the TTL.

Create a new controller to monitor vulnerability reports, using [RequeueAfter](https://pkg.go.dev/sigs.k8s.io/controller-runtime/pkg/reconcile#Result) based on the TTL annotation. On startup, the operator checks existing reports and deletes expired ones. Reports with valid TTLs are requeued and checked automatically when the TTL expires.

Explicitly annotating reports shows users how long each report will exist, improving visibility.

### Example

Below is a shortened version of the YAML. Notice the `metadata.annotations.trivy-operator.aquasecurity.github.io/report-ttl`, automatically set if `operator.scannerReportTTL` or `OPERATOR_SCANNER_REPORT_TTL` is configured. Users can manually change TTL per report.

```vulnerabilityReport.yaml
apiVersion: aquasecurity.github.io/v1alpha1
kind: VulnerabilityReport
metadata:
  creationTimestamp: "2021-12-08T12:03:48Z"
  annotations:
    trivy-operator.aquasecurity.github.io/report-ttl: 12h30m0s
  labels:
    resource-spec-hash: 86b58dcb99
    trivy-operator.container.name: manager
    trivy-operator.resource.kind: ReplicaSet
    trivy-operator.resource.name: source-controller-b5d5cfdf4
    trivy-operator.resource.namespace: flux-system
  name: replicaset-source-controller-b5d5cfdf4-manager
report:
  artifact:
    repository: fluxcd/source-controller
    tag: v1.4.1
  registry:
    server: ghcr.io
  scanner:
    name: Trivy
    vendor: Aqua Security
    version: 0.62.0
  summary:
    criticalCount: 0
    highCount: 0
    lowCount: 0
    mediumCount: 0
    unknownCount: 0
  updateTimestamp: "2021-12-08T12:03:48Z"
  vulnerabilities: []
```
