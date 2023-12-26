# ExposedSecretReport

An instance of the `ExposedSecretReport` represents the secrets found in a container image of a given
Kubernetes workload. It consists of a list exposed secrets with a summary grouped by severity. For a multi-container workload the Trivy Operator will create multiple instances of the `ExposedSecretsReports` in the workload's namespace with the owner reference set to that workload.
Each report follows the naming convention `<workload kind>-<workload name>-<container-name>`.

The following listing shows a sample `ExposedSecretReport` associated with the ReplicaSet named `app-574ddcb559` in the
`default` namespace that has the `app` container.

```yaml
apiVersion: aquasecurity.github.io/v1alpha1
kind: ExposedSecretReport
metadata:
  creationTimestamp: "2022-06-29T14:25:54Z"
  generation: 2
  labels:
    resource-spec-hash: 8495697ff5
    trivy-operator.container.name: app
    trivy-operator.resource.kind: ReplicaSet
    trivy-operator.resource.name: app-67b77f5965
    trivy-operator.resource.namespace: default
  name: replicaset-app-67b77f5965-app
  namespace: default
  ownerReferences:
  - apiVersion: apps/v1
    blockOwnerDeletion: false
    controller: true
    kind: ReplicaSet
    name: app-67b77f5965
    uid: 04a744fe-1126-42d5-bb8b-0917bdb51a28
  resourceVersion: "1420"
  uid: 2b2697bb-d528-4d4d-8312-a74dcab6ac65
report:
  artifact:
    repository: myimagewithsecret
    tag: v0.18.0-rc
  registry:
    server: index.docker.io
  scanner:
    name: Trivy
    vendor: Aqua Security
    version: 0.35.0
  secrets:
  - category: Stripe
    match: 'publishable_key: *****'
    ruleID: stripe-access-token
    severity: HIGH
    target: "/app/config/secret.yaml"
    title: Stripe
  - category: Stripe
    match: 'secret_key: *****'
    ruleID: stripe-access-token
    severity: HIGH
    target: "/app/config/secret.yaml"
    title: Stripe
  summary:
    criticalCount: 0
    highCount: 2
    lowCount: 0
    mediumCount: 0
  updateTimestamp: "2022-06-29T14:29:37Z"
```
