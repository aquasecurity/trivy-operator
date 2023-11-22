# Configuration Auditing

## Setting
The following flags can be set with the `trivy-operator-trivy-config` ConfigMap in order to impact scanning

| CONFIGMAP KEY                     | DEFAULT                                                                               | DESCRIPTION                                                                                                     |
|-----------------------------------|---------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------|
| `trivy.useBuiltinRegoPolicies`    | `true`                                                                                | The Flag to enable the usage of builtin rego policies by default                                                |
| `trivy.supportedConfigAuditKinds` | `Workload,Service,Role,ClusterRole,NetworkPolicy,Ingress,LimitRange,ResourceQuota`    | The Flag is the list of supported kinds separated by comma delimiter to be scanned by the config audit scanner  |


As your organization deploys containerized workloads in Kubernetes environments, you will be faced with many
configuration choices related to images, containers, control plane, and data plane. Setting these configurations
improperly creates a high-impact security and compliance risk. DevOps, and platform owners need the ability to
continuously assess build artifacts, workloads, and infrastructure against configuration hardening standards to
remediate any violations.

trivy-operator configuration audit capabilities are purpose-built for Kubernetes environments. In particular, the Trivy
Operator continuously checks images, workloads, and Kubernetes infrastructure components against common configurations
security standards and generates detailed assessment reports, which are then stored in the default Kubernetes database.

Kubernetes applications and other core configuration objects, such as Ingress, NetworkPolicy and ResourceQuota resources, are evaluated against [Built-in Policies]. 
Additionally, application and infrastructure owners can integrate these reports into incident response workflows for
active remediation.

[Built-in Policies]: ./built-in-policies.md

