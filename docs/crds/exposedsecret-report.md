# ExposedSecretReport

An instance of the ExposedSecretReport represents the secrets found in a container image of a given
Kubernetes workload. It consists of a list exposed secrets with a summary grouped by severity. For a multi-container workload trivy-operator creates multiple instances
of ExposedSecretsReports in the workload's namespace with the owner reference set to that workload.
Each report follows the naming convention `<workload kind>-<workload name>-<container-name>`.

The following listing shows a sample ExposedSecretReport associated with the ReplicaSet named `app-574ddcb559` in the
`default` namespace that has the `app` container.

```yaml
Name:         replicaset-app-574ddcb559-app
Namespace:    default
Labels:       resource-spec-hash=8495697ff5
              trivy-operator.container.name=app
              trivy-operator.resource.kind=ReplicaSet
              trivy-operator.resource.name=app-574ddcb559
              trivy-operator.resource.namespace=default
Annotations:  <none>
API Version:  aquasecurity.github.io/v1alpha1
Kind:         ExposedSecretReport
Metadata:
  Creation Timestamp:  2022-06-20T23:32:30Z
  Generation:          1
  Owner References:
    API Version:           apps/v1
    Block Owner Deletion:  false
    Controller:            true
    Kind:                  ReplicaSet
    Name:                  app-574ddcb559
    UID:                   5782a883-c4d2-4051-be09-f7c1650d36d0
  Resource Version:        7450
  UID:                     220a3e87-f64b-42d4-a7cb-cf592a5514b2
Report:
  Artifact:
    Repository:  myimagewithsecret
    Tag:         v0.1.0
  Registry:
    Server:  index.docker.io
  Scanner:
    Name:     Trivy
    Vendor:   Aqua Security
    Version:  0.28.1
  Secrets:
    Category:  Stripe
    Match:     publishable_key: *****
    Rule ID:   stripe-access-token
    Severity:  HIGH
    Target:
    Title:     Stripe
    Category:  Stripe
    Match:     secret_key: *****
    Rule ID:   stripe-access-token
    Severity:  HIGH
    Target:
    Title:     Stripe
  Summary:
    Critical Count:  0
    High Count:      2
    Low Count:       0
    Medium Count:    0
    None Count:      0
```
