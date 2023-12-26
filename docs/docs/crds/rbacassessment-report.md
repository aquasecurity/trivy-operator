# RbacAssessmentReport

An instance of the RbacAssessmentReport represents checks performed by configuration auditing tools, such as [Trivy](https://github.com/aquasecurity/trivy), against a Kubernetes RBAC assessment. For example, check that a given Role does not expose permission to secrets for all groups.

Each report is owned by the underlying Kubernetes object and is stored in the same namespace, following the
`<Role>-<role-name>` naming convention.

The following listing shows a sample RbacAssessmentReport associated with the Role named `role-868458b9d6` in the
`default` namespace.

```yaml
apiVersion: aquasecurity.github.io/v1alpha1
kind: RbacAssessmentReport
metadata:
  annotations:
    trivy-operator.resource.name: system:controller:token-cleaner
  creationTimestamp: "2022-07-04T07:23:07Z"
  generation: 1
  labels:
    plugin-config-hash: 659b7b9c46
    resource-spec-hash: 59b6bf95c6
    trivy-operator.resource.kind: Role
    trivy-operator.resource.name-hash: 868458b9d6
    trivy-operator.resource.namespace: default
  name: role-868458b9d6
  namespace: kube-system
  ownerReferences:
    - apiVersion: rbac.authorization.k8s.io/v1
      blockOwnerDeletion: false
      controller: true
      kind: Role
      name: system:controller:token-cleaner
      uid: 44c6229b-d410-4bc5-9529-fff41de39d03
  resourceVersion: "7301"
  uid: 372d7c32-795f-4180-ae84-efd931efaf6e
report:
  checks:
    - category: Kubernetes Security Check
      checkID: KSV051
      description: Check whether role permits creating role bindings and associating
        to privileged role/clusterrole
      messages:
        - ""
      severity: HIGH
      success: true
      title: Do not allow role binding creation and association with privileged role/clusterrole
    - category: Kubernetes Security Check
      checkID: KSV056
      description: The ability to control which pods get service traffic directed to
        them allows for interception attacks. Controlling network policy allows for
        bypassing lateral movement restrictions.
      messages:
        - ""
      severity: HIGH
      success: true
      title: Do not allow management of networking resources
    - category: Kubernetes Security Check
      checkID: KSV041
      description: Check whether role permits managing secrets
      messages:
        - Role permits management of secret(s)
      severity: CRITICAL
      success: false
      title: Do not allow management of secrets
    - category: Kubernetes Security Check
      checkID: KSV047
      description: Check whether role permits privilege escalation from node proxy
      messages:
        - ""
      severity: HIGH
      success: true
      title: Do not allow privilege escalation from node proxy
    - category: Kubernetes Security Check
      checkID: KSV045
      description: Check whether role permits wildcard verb on specific resources
      messages:
        - ""
      severity: CRITICAL
      success: true
      title: No wildcard verb roles
    - category: Kubernetes Security Check
      checkID: KSV054
      description: Check whether role permits attaching to shell on pods
      messages:
        - ""
      severity: HIGH
      success: true
      title: Do not allow attaching to shell on pods
    - category: Kubernetes Security Check
      checkID: KSV044
      description: Check whether role permits wildcard verb on wildcard resource
      messages:
        - ""
      severity: CRITICAL
      success: true
      title: No wildcard verb and resource roles
    - category: Kubernetes Security Check
      checkID: KSV050
      description: An effective level of access equivalent to cluster-admin should not
        be provided.
      messages:
        - ""
      severity: CRITICAL
      success: true
      title: Do not allow management of RBAC resources
    - category: Kubernetes Security Check
      checkID: KSV046
      description: Check whether role permits specific verb on wildcard resources
      messages:
        - ""
      severity: CRITICAL
      success: true
      title: No wildcard resource roles
    - category: Kubernetes Security Check
      checkID: KSV055
      description: Check whether role permits allowing users in a rolebinding to add
        other users to their rolebindings
      messages:
        - ""
      severity: LOW
      success: true
      title: Do not allow users in a rolebinding to add other users to their rolebindings
    - category: Kubernetes Security Check
      checkID: KSV052
      description: Check whether role permits creating role ClusterRoleBindings and
        association with privileged cluster role
      messages:
        - ""
      severity: HIGH
      success: true
      title: Do not allow role to create ClusterRoleBindings and association with privileged
        role
    - category: Kubernetes Security Check
      checkID: KSV053
      description: Check whether role permits getting shell on pods
      messages:
        - ""
      severity: HIGH
      success: true
      title: Do not allow getting shell on pods
    - category: Kubernetes Security Check
      checkID: KSV042
      description: Used to cover attacker’s tracks, but most clusters ship logs quickly
        off-cluster.
      messages:
        - ""
      severity: MEDIUM
      success: true
      title: Do not allow deletion of pod logs
    - category: Kubernetes Security Check
      checkID: KSV049
      description: Some workloads leverage configmaps to store sensitive data or configuration
        parameters that affect runtime behavior that can be modified by an attacker
        or combined with another issue to potentially lead to compromise.
      messages:
        - ""
      severity: MEDIUM
      success: true
      title: Do not allow management of configmaps
    - category: Kubernetes Security Check
      checkID: KSV043
      description: Check whether role permits impersonating privileged groups
      messages:
        - ""
      severity: CRITICAL
      success: true
      title: Do not allow impersonation of privileged groups
    - category: Kubernetes Security Check
      checkID: KSV048
      description: Check whether role permits update/create of a malicious pod
      messages:
        - ""
      severity: HIGH
      success: true
      title: Do not allow update/create of a malicious pod
  scanner:
    name: Trivy
    vendor: Aqua Security
    version: '0.18.0-rc'
  summary:
    criticalCount: 1
    highCount: 0
    lowCount: 0
    mediumCount: 0
  updateTimestamp: null
```
