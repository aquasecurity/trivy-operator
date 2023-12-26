# ClusterComplianceReport

The ClusterComplianceReport is a cluster-scoped resource, which represents the latest compliance control check results.
The report spec defines a mapping between pre-defined compliance control check ids to security scanners check ids.
Currently, only `config-audit` security scanners are supported.

## Built in reports

The following reports are available out of the box:

| Compliance | Name for command | More info
--- | --- | ---
NSA, CISA Kubernetes Hardening Guidance v1.2 | `nsa` | [Link](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF)
CIS Benchmark for Kubernetes v1.23 | `cis` | [Link](https://www.cisecurity.org/benchmark/kubernetes)

### The compliance report structure

- `spec:` represents the compliance control checks specification, check details, and the mapping to the security scanner
  (this part is defined by the user)
- `status:` represents the compliance control checks (as defined by spec mapping) results extracted from the security
  scanners reports (this part is output by trivy-operator)

The following shows a sample ClusterComplianceReport NSA specification associated with the `cluster` in summary format:

<details>

<summary>NSA, CISA Kubernetes Hardening Guidance v1.2</summary>

```yaml
apiVersion: aquasecurity.github.io/v1alpha1
kind: ClusterComplianceReport
metadata:
  creationTimestamp: "2022-12-04T18:25:27Z"
  generation: 3
  labels:
    app.kubernetes.io/instance: trivy-operator
    app.kubernetes.io/managed-by: kubectl
    app.kubernetes.io/name: trivy-operator
    app.kubernetes.io/version: 0.8.0
  name: nsa
  resourceVersion: "69736"
  uid: d9991808-fb2f-4756-842f-8e9205e85b71
spec:
  compliance:
    controls:
    - checks:
      - id: AVD-KSV-0012
      description: Check that container is not running as root
      id: "1.0"
      name: Non-root containers
      severity: MEDIUM
    - checks:
      - id: AVD-KSV-0014
      description: Check that container root file system is immutable
      id: "1.1"
      name: Immutable container file systems
      severity: LOW
    - checks:
      - id: AVD-KSV-0017
      description: Controls whether Pods can run privileged containers
      id: "1.2"
      name: Preventing privileged containers
      severity: HIGH
    - checks:
      - id: AVD-KSV-0008
      description: Controls whether containers can share process namespaces
      id: "1.3"
      name: Share containers process namespaces
      severity: HIGH
    - checks:
      - id: AVD-KSV-0009
      description: Controls whether share host process namespaces
      id: "1.4"
      name: Share host process namespaces
      severity: HIGH
    - checks:
      - id: AVD-KSV-0010
      description: Controls whether containers can use the host network
      id: "1.5"
      name: Use the host network
      severity: HIGH
    - checks:
      - id: AVD-KSV-0029
      description: Controls whether container applications can run with root privileges
        or with root group membership
      id: "1.6"
      name: Run with root privileges or with root group membership
      severity: LOW
    - checks:
      - id: AVD-KSV-0001
      description: Control check restrictions escalation to root privileges
      id: "1.7"
      name: Restricts escalation to root privileges
      severity: MEDIUM
    - checks:
      - id: AVD-KSV-0002
      description: Control checks if pod sets the SELinux context of the container
      id: "1.8"
      name: Sets the SELinux context of the container
      severity: MEDIUM
    - checks:
      - id: AVD-KSV-0030
      description: Control checks the restriction of containers access to resources
        with AppArmor
      id: "1.9"
      name: Restrict a container's access to resources with AppArmor
      severity: MEDIUM
    - checks:
      - id: AVD-KSV-0030
      description: Control checks the sets the seccomp profile used to sandbox containers
      id: "1.10"
      name: Sets the seccomp profile used to sandbox containers.
      severity: LOW
    - checks:
      - id: AVD-KSV-0036
      description: 'Control check whether disable secret token been mount ,automountServiceAccountToken:
        false'
      id: "1.11"
      name: Protecting Pod service account tokens
      severity: MEDIUM
    - checks:
      - id: AVD-KSV-0037
      defaultStatus: FAIL
      description: Control check whether Namespace kube-system is not be used by users
      id: "1.12"
      name: Namespace kube-system should not be used by users
      severity: MEDIUM
    - checks:
      - id: AVD-KSV-0038
      defaultStatus: FAIL
      description: Control check validate the pod and/or namespace Selectors usage
      id: "2.0"
      name: Pod and/or namespace Selectors usage
      severity: MEDIUM
    - defaultStatus: FAIL
      description: Control check whether check cni plugin installed
      id: "3.0"
      name: Use CNI plugin that supports NetworkPolicy API (Manual)
      severity: CRITICAL
    - checks:
      - id: AVD-KSV-0040
      defaultStatus: FAIL
      description: Control check the use of ResourceQuota policy to limit aggregate
        resource usage within namespace
      id: "4.0"
      name: Use ResourceQuota policies to limit resources
      severity: MEDIUM
    - checks:
      - id: AVD-KSV-0039
      defaultStatus: FAIL
      description: Control check the use of LimitRange policy limit resource usage
        for namespaces or nodes
      id: "4.1"
      name: Use LimitRange policies to limit resources
      severity: MEDIUM
    - defaultStatus: FAIL
      description: Control check whether control plan disable insecure port
      id: "5.0"
      name: Control plan disable insecure port (Manual)
      severity: CRITICAL
    - checks:
      - id: AVD-KCV-0030
      description: Control check whether etcd communication is encrypted
      id: "5.1"
      name: Encrypt etcd communication
      severity: CRITICAL
    - defaultStatus: FAIL
      description: Control check whether kube config file permissions
      id: "6.0"
      name: Ensure kube config file permission (Manual)
      severity: CRITICAL
    - checks:
      - id: AVD-KCV-0029
      description: Control checks whether encryption resource has been set
      id: "6.1"
      name: Check that encryption resource has been set
      severity: CRITICAL
    - checks:
      - id: AVD-KCV-0004
      description: Control checks whether encryption provider has been set
      id: "6.2"
      name: Check encryption provider
      severity: CRITICAL
    - checks:
      - id: AVD-KCV-0001
      description: Control checks whether anonymous-auth is unset
      id: "7.0"
      name: Make sure anonymous-auth is unset
      severity: CRITICAL
    - checks:
      - id: AVD-KCV-0008
      description: Control check whether RBAC permission is in use
      id: "7.1"
      name: Make sure -authorization-mode=RBAC
      severity: CRITICAL
    - defaultStatus: FAIL
      description: Control check whether audit policy is configure
      id: "8.0"
      name: Audit policy is configure (Manual)
      severity: HIGH
    - checks:
      - id: AVD-KCV-0019
      description: Control check whether audit log path is configure
      id: "8.1"
      name: Audit log path is configure
      severity: MEDIUM
    - checks:
      - id: AVD-KCV-0020
      description: Control check whether audit log aging is configure
      id: "8.2"
      name: Audit log aging
      severity: MEDIUM
    description: National Security Agency - Kubernetes Hardening Guidance
    id: "0001"
    relatedResources:
    - https://www.nsa.gov/Press-Room/News-Highlights/Article/Article/2716980/nsa-cisa-release-kubernetes-hardening-guidance/
    title: nsa
    version: "1.0"
  cron: '* * * * *'
  reportType: summary
status:
  summaryReport:
    controlCheck:
    - id: "1.0"
      name: Non-root containers
      severity: MEDIUM
      totalFail: 8
    - id: "1.1"
      name: Immutable container file systems
      severity: LOW
      totalFail: 7
    - id: "1.2"
      name: Preventing privileged containers
      severity: HIGH
      totalFail: 1
    - id: "1.3"
      name: Share containers process namespaces
      severity: HIGH
      totalFail: 0
    - id: "1.4"
      name: Share host process namespaces
      severity: HIGH
      totalFail: 6
    - id: "1.5"
      name: Use the host network
      severity: HIGH
      totalFail: 0
    - id: "1.6"
      name: Run with root privileges or with root group membership
      severity: LOW
      totalFail: 0
    - id: "1.7"
      name: Restricts escalation to root privileges
      severity: MEDIUM
      totalFail: 7
    - id: "1.8"
      name: Sets the SELinux context of the container
      severity: MEDIUM
      totalFail: 0
    - id: "1.9"
      name: Restrict a container's access to resources with AppArmor
      severity: MEDIUM
      totalFail: 8
    - id: "1.10"
      name: Sets the seccomp profile used to sandbox containers.
      severity: LOW
      totalFail: 8
    - id: "1.11"
      name: Protecting Pod service account tokens
      severity: MEDIUM
      totalFail: 0
    - id: "1.12"
      name: Namespace kube-system should not be used by users
      severity: MEDIUM
      totalFail: 4
    - id: "2.0"
      name: Pod and/or namespace Selectors usage
      severity: MEDIUM
      totalFail: 0
    - id: "3.0"
      name: Use CNI plugin that supports NetworkPolicy API (Manual)
      severity: CRITICAL
    - id: "4.0"
      name: Use ResourceQuota policies to limit resources
      severity: MEDIUM
      totalFail: 0
    - id: "4.1"
      name: Use LimitRange policies to limit resources
      severity: MEDIUM
      totalFail: 0
    - id: "5.0"
      name: Control plan disable insecure port (Manual)
      severity: CRITICAL
    - id: "5.1"
      name: Encrypt etcd communication
      severity: CRITICAL
      totalFail: 0
    - id: "6.0"
      name: Ensure kube config file permission (Manual)
      severity: CRITICAL
    - id: "6.1"
      name: Check that encryption resource has been set
      severity: CRITICAL
      totalFail: 1
    - id: "6.2"
      name: Check encryption provider
      severity: CRITICAL
      totalFail: 0
    - id: "7.0"
      name: Make sure anonymous-auth is unset
      severity: CRITICAL
      totalFail: 1
    - id: "7.1"
      name: Make sure -authorization-mode=RBAC
      severity: CRITICAL
      totalFail: 0
    - id: "8.0"
      name: Audit policy is configure (Manual)
      severity: HIGH
    - id: "8.1"
      name: Audit log path is configure
      severity: MEDIUM
      totalFail: 1
    - id: "8.2"
      name: Audit log aging
      severity: MEDIUM
      totalFail: 1
    id: "0001"
    title: nsa
  totalCounts:
    failCount: 12
    passCount: 15
  updateTimestamp: "2022-12-05T12:21:30Z"
```

The following shows a sample ClusterComplianceReport NSA specification associated with the `cluster` in detail(all) format:

```yaml
apiVersion: aquasecurity.github.io/v1alpha1
kind: ClusterComplianceReport
metadata:
  annotations:
  creationTimestamp: "2022-12-04T18:25:27Z"
  generation: 2
  labels:
    app.kubernetes.io/instance: trivy-operator
    app.kubernetes.io/managed-by: kubectl
    app.kubernetes.io/name: trivy-operator
    app.kubernetes.io/version: 0.8.0
  name: nsa
  resourceVersion: "50896"
  uid: d9991808-fb2f-4756-842f-8e9205e85b71
spec:
  compliance:
    controls:
    - checks:
      - id: AVD-KSV-0012
      description: Check that container is not running as root
      id: "1.0"
      name: Non-root containers
      severity: MEDIUM
    - checks:
      - id: AVD-KSV-0014
      description: Check that container root file system is immutable
      id: "1.1"
      name: Immutable container file systems
      severity: LOW
    - checks:
      - id: AVD-KSV-0017
      description: Controls whether Pods can run privileged containers
      id: "1.2"
      name: Preventing privileged containers
      severity: HIGH
    - checks:
      - id: AVD-KSV-0008
      description: Controls whether containers can share process namespaces
      id: "1.3"
      name: Share containers process namespaces
      severity: HIGH
    - checks:
      - id: AVD-KSV-0009
      description: Controls whether share host process namespaces
      id: "1.4"
      name: Share host process namespaces
      severity: HIGH
    - checks:
      - id: AVD-KSV-0010
      description: Controls whether containers can use the host network
      id: "1.5"
      name: Use the host network
      severity: HIGH
    - checks:
      - id: AVD-KSV-0029
      description: Controls whether container applications can run with root privileges
        or with root group membership
      id: "1.6"
      name: Run with root privileges or with root group membership
      severity: LOW
    - checks:
      - id: AVD-KSV-0001
      description: Control check restrictions escalation to root privileges
      id: "1.7"
      name: Restricts escalation to root privileges
      severity: MEDIUM
    - checks:
      - id: AVD-KSV-0002
      description: Control checks if pod sets the SELinux context of the container
      id: "1.8"
      name: Sets the SELinux context of the container
      severity: MEDIUM
    - checks:
      - id: AVD-KSV-0030
      description: Control checks the restriction of containers access to resources
        with AppArmor
      id: "1.9"
      name: Restrict a container's access to resources with AppArmor
      severity: MEDIUM
    - checks:
      - id: AVD-KSV-0030
      description: Control checks the sets the seccomp profile used to sandbox containers
      id: "1.10"
      name: Sets the seccomp profile used to sandbox containers.
      severity: LOW
    - checks:
      - id: AVD-KSV-0036
      description: 'Control check whether disable secret token been mount ,automountServiceAccountToken:
        false'
      id: "1.11"
      name: Protecting Pod service account tokens
      severity: MEDIUM
    - checks:
      - id: AVD-KSV-0037
      defaultStatus: FAIL
      description: Control check whether Namespace kube-system is not be used by users
      id: "1.12"
      name: Namespace kube-system should not be used by users
      severity: MEDIUM
    - checks:
      - id: AVD-KSV-0038
      defaultStatus: FAIL
      description: Control check validate the pod and/or namespace Selectors usage
      id: "2.0"
      name: Pod and/or namespace Selectors usage
      severity: MEDIUM
    - defaultStatus: FAIL
      description: Control check whether check cni plugin installed
      id: "3.0"
      name: Use CNI plugin that supports NetworkPolicy API (Manual)
      severity: CRITICAL
    - checks:
      - id: AVD-KSV-0040
      defaultStatus: FAIL
      description: Control check the use of ResourceQuota policy to limit aggregate
        resource usage within namespace
      id: "4.0"
      name: Use ResourceQuota policies to limit resources
      severity: MEDIUM
    - checks:
      - id: AVD-KSV-0039
      defaultStatus: FAIL
      description: Control check the use of LimitRange policy limit resource usage
        for namespaces or nodes
      id: "4.1"
      name: Use LimitRange policies to limit resources
      severity: MEDIUM
    - defaultStatus: FAIL
      description: Control check whether control plan disable insecure port
      id: "5.0"
      name: Control plan disable insecure port (Manual)
      severity: CRITICAL
    - checks:
      - id: AVD-KCV-0030
      description: Control check whether etcd communication is encrypted
      id: "5.1"
      name: Encrypt etcd communication
      severity: CRITICAL
    - defaultStatus: FAIL
      description: Control check whether kube config file permissions
      id: "6.0"
      name: Ensure kube config file permission (Manual)
      severity: CRITICAL
    - checks:
      - id: AVD-KCV-0029
      description: Control checks whether encryption resource has been set
      id: "6.1"
      name: Check that encryption resource has been set
      severity: CRITICAL
    - checks:
      - id: AVD-KCV-0004
      description: Control checks whether encryption provider has been set
      id: "6.2"
      name: Check encryption provider
      severity: CRITICAL
    - checks:
      - id: AVD-KCV-0001
      description: Control checks whether anonymous-auth is unset
      id: "7.0"
      name: Make sure anonymous-auth is unset
      severity: CRITICAL
    - checks:
      - id: AVD-KCV-0008
      description: Control check whether RBAC permission is in use
      id: "7.1"
      name: Make sure -authorization-mode=RBAC
      severity: CRITICAL
    - defaultStatus: FAIL
      description: Control check whether audit policy is configure
      id: "8.0"
      name: Audit policy is configure (Manual)
      severity: HIGH
    - checks:
      - id: AVD-KCV-0019
      description: Control check whether audit log path is configure
      id: "8.1"
      name: Audit log path is configure
      severity: MEDIUM
    - checks:
      - id: AVD-KCV-0020
      description: Control check whether audit log aging is configure
      id: "8.2"
      name: Audit log aging
      severity: MEDIUM
    description: National Security Agency - Kubernetes Hardening Guidance
    id: "0001"
    relatedResources:
    - https://www.nsa.gov/Press-Room/News-Highlights/Article/Article/2716980/nsa-cisa-release-kubernetes-hardening-guidance/
    title: nsa
    version: "1.0"
  cron: '* * * * *'
  reportType: all
status:
  detailReport:
    description: National Security Agency - Kubernetes Hardening Guidance
    id: "0001"
    relatedVersion:
    - https://www.nsa.gov/Press-Room/News-Highlights/Article/Article/2716980/nsa-cisa-release-kubernetes-hardening-guidance/
    results:
    - checks:
      - category: Kubernetes Security Check
        checkID: AVD-KSV-0012
        description: '''runAsNonRoot'' forces the running image to run as a non-root
          user to ensure least privileges.'
        messages:
        - '''runAsNonRoot'' forces the running image to run as a non-root user to
          ensure least privileges.'
        severity: MEDIUM
        success: false
        target: kube-system/pod-etcd-kind-control-plane
        title: Runs as root user
      - category: Kubernetes Security Check
        checkID: AVD-KSV-0012
        description: '''runAsNonRoot'' forces the running image to run as a non-root
          user to ensure least privileges.'
        messages:
        - '''runAsNonRoot'' forces the running image to run as a non-root user to
          ensure least privileges.'
        severity: MEDIUM
        success: false
        target: kube-system/replicaset-coredns-558bd4d5db
        title: Runs as root user
      - category: Kubernetes Security Check
        checkID: AVD-KSV-0012
        description: '''runAsNonRoot'' forces the running image to run as a non-root
          user to ensure least privileges.'
        messages:
        - '''runAsNonRoot'' forces the running image to run as a non-root user to
          ensure least privileges.'
        severity: MEDIUM
        success: false
        target: kube-system/daemonset-kindnet
        title: Runs as root user
      - category: Kubernetes Security Check
        checkID: AVD-KSV-0012
        description: '''runAsNonRoot'' forces the running image to run as a non-root
          user to ensure least privileges.'
        messages:
        - '''runAsNonRoot'' forces the running image to run as a non-root user to
          ensure least privileges.'
        severity: MEDIUM
        success: false
        target: kube-system/pod-kube-apiserver-kind-control-plane
        title: Runs as root user
      - category: Kubernetes Security Check
        checkID: AVD-KSV-0012
        description: '''runAsNonRoot'' forces the running image to run as a non-root
          user to ensure least privileges.'
        messages:
        - '''runAsNonRoot'' forces the running image to run as a non-root user to
          ensure least privileges.'
        severity: MEDIUM
        success: false
        target: kube-system/daemonset-kube-proxy
        title: Runs as root user
      - category: Kubernetes Security Check
        checkID: AVD-KSV-0012
        description: '''runAsNonRoot'' forces the running image to run as a non-root
          user to ensure least privileges.'
        messages:
        - '''runAsNonRoot'' forces the running image to run as a non-root user to
          ensure least privileges.'
        severity: MEDIUM
        success: false
        target: kube-system/pod-kube-scheduler-kind-control-plane
        title: Runs as root user
      - category: Kubernetes Security Check
        checkID: AVD-KSV-0012
        description: '''runAsNonRoot'' forces the running image to run as a non-root
          user to ensure least privileges.'
        messages:
        - '''runAsNonRoot'' forces the running image to run as a non-root user to
          ensure least privileges.'
        severity: MEDIUM
        success: false
        target: local-path-storage/replicaset-local-path-provisioner-547f784dff
        title: Runs as root user
      - category: Kubernetes Security Check
        checkID: AVD-KSV-0012
        description: '''runAsNonRoot'' forces the running image to run as a non-root
          user to ensure least privileges.'
        messages:
        - '''runAsNonRoot'' forces the running image to run as a non-root user to
          ensure least privileges.'
        severity: MEDIUM
        success: false
        target: kube-system/pod-kube-controller-manager-kind-control-plane
        title: Runs as root user
      description: Check that container is not running as root
      id: "1.0"
      name: Non-root containers
      severity: MEDIUM
    - checks:
      - category: Kubernetes Security Check
        checkID: AVD-KSV-0014
        description: An immutable root file system prevents applications from writing
          to their local disk. This can limit intrusions, as attackers will not be
          able to tamper with the file system or write foreign executables to disk.
        messages:
        - An immutable root file system prevents applications from writing to their
          local disk. This can limit intrusions, as attackers will not be able to
          tamper with the file system or write foreign executables to disk.
        severity: LOW
        success: false
        target: kube-system/pod-etcd-kind-control-plane
        title: Root file system is not read-only
      - category: Kubernetes Security Check
        checkID: AVD-KSV-0014
        description: An immutable root file system prevents applications from writing
          to their local disk. This can limit intrusions, as attackers will not be
          able to tamper with the file system or write foreign executables to disk.
        messages:
        - An immutable root file system prevents applications from writing to their
          local disk. This can limit intrusions, as attackers will not be able to
          tamper with the file system or write foreign executables to disk.
        severity: LOW
        success: false
        target: kube-system/daemonset-kindnet
        title: Root file system is not read-only
      - category: Kubernetes Security Check
        checkID: AVD-KSV-0014
        description: An immutable root file system prevents applications from writing
          to their local disk. This can limit intrusions, as attackers will not be
          able to tamper with the file system or write foreign executables to disk.
        messages:
        - An immutable root file system prevents applications from writing to their
          local disk. This can limit intrusions, as attackers will not be able to
          tamper with the file system or write foreign executables to disk.
        severity: LOW
        success: false
        target: kube-system/pod-kube-apiserver-kind-control-plane
        title: Root file system is not read-only
      - category: Kubernetes Security Check
        checkID: AVD-KSV-0014
        description: An immutable root file system prevents applications from writing
          to their local disk. This can limit intrusions, as attackers will not be
          able to tamper with the file system or write foreign executables to disk.
        messages:
        - An immutable root file system prevents applications from writing to their
          local disk. This can limit intrusions, as attackers will not be able to
          tamper with the file system or write foreign executables to disk.
        severity: LOW
        success: false
        target: kube-system/daemonset-kube-proxy
        title: Root file system is not read-only
      - category: Kubernetes Security Check
        checkID: AVD-KSV-0014
        description: An immutable root file system prevents applications from writing
          to their local disk. This can limit intrusions, as attackers will not be
          able to tamper with the file system or write foreign executables to disk.
        messages:
        - An immutable root file system prevents applications from writing to their
          local disk. This can limit intrusions, as attackers will not be able to
          tamper with the file system or write foreign executables to disk.
        severity: LOW
        success: false
        target: kube-system/pod-kube-scheduler-kind-control-plane
        title: Root file system is not read-only
      - category: Kubernetes Security Check
        checkID: AVD-KSV-0014
        description: An immutable root file system prevents applications from writing
          to their local disk. This can limit intrusions, as attackers will not be
          able to tamper with the file system or write foreign executables to disk.
        messages:
        - An immutable root file system prevents applications from writing to their
          local disk. This can limit intrusions, as attackers will not be able to
          tamper with the file system or write foreign executables to disk.
        severity: LOW
        success: false
        target: local-path-storage/replicaset-local-path-provisioner-547f784dff
        title: Root file system is not read-only
      - category: Kubernetes Security Check
        checkID: AVD-KSV-0014
        description: An immutable root file system prevents applications from writing
          to their local disk. This can limit intrusions, as attackers will not be
          able to tamper with the file system or write foreign executables to disk.
        messages:
        - An immutable root file system prevents applications from writing to their
          local disk. This can limit intrusions, as attackers will not be able to
          tamper with the file system or write foreign executables to disk.
        severity: LOW
        success: false
        target: kube-system/pod-kube-controller-manager-kind-control-plane
        title: Root file system is not read-only
      description: Check that container root file system is immutable
      id: "1.1"
      name: Immutable container file systems
      severity: LOW
    - checks:
      - category: Kubernetes Security Check
        checkID: AVD-KSV-0017
        description: Privileged containers share namespaces with the host system and
          do not offer any security. They should be used exclusively for system containers
          that require high privileges.
        messages:
        - Privileged containers share namespaces with the host system and do not offer
          any security. They should be used exclusively for system containers that
          require high privileges.
        severity: HIGH
        success: false
        target: kube-system/daemonset-kube-proxy
        title: Privileged container
      description: Controls whether Pods can run privileged containers
      id: "1.2"
      name: Preventing privileged containers
      severity: HIGH
    - checks:
      - checkID: ""
        severity: ""
        success: true
      description: Controls whether containers can share process namespaces
      id: "1.3"
      name: Share containers process namespaces
      severity: HIGH
    - checks:
      - category: Kubernetes Security Check
        checkID: AVD-KSV-0009
        description: Sharing the host’s network namespace permits processes in the
          pod to communicate with processes bound to the host’s loopback adapter.
        messages:
        - Sharing the host’s network namespace permits processes in the pod to communicate
          with processes bound to the host’s loopback adapter.
        severity: HIGH
        success: false
        target: kube-system/pod-etcd-kind-control-plane
        title: Access to host network
      - category: Kubernetes Security Check
        checkID: AVD-KSV-0009
        description: Sharing the host’s network namespace permits processes in the
          pod to communicate with processes bound to the host’s loopback adapter.
        messages:
        - Sharing the host’s network namespace permits processes in the pod to communicate
          with processes bound to the host’s loopback adapter.
        severity: HIGH
        success: false
        target: kube-system/daemonset-kindnet
        title: Access to host network
      - category: Kubernetes Security Check
        checkID: AVD-KSV-0009
        description: Sharing the host’s network namespace permits processes in the
          pod to communicate with processes bound to the host’s loopback adapter.
        messages:
        - Sharing the host’s network namespace permits processes in the pod to communicate
          with processes bound to the host’s loopback adapter.
        severity: HIGH
        success: false
        target: kube-system/pod-kube-apiserver-kind-control-plane
        title: Access to host network
      - category: Kubernetes Security Check
        checkID: AVD-KSV-0009
        description: Sharing the host’s network namespace permits processes in the
          pod to communicate with processes bound to the host’s loopback adapter.
        messages:
        - Sharing the host’s network namespace permits processes in the pod to communicate
          with processes bound to the host’s loopback adapter.
        severity: HIGH
        success: false
        target: kube-system/daemonset-kube-proxy
        title: Access to host network
      - category: Kubernetes Security Check
        checkID: AVD-KSV-0009
        description: Sharing the host’s network namespace permits processes in the
          pod to communicate with processes bound to the host’s loopback adapter.
        messages:
        - Sharing the host’s network namespace permits processes in the pod to communicate
          with processes bound to the host’s loopback adapter.
        severity: HIGH
        success: false
        target: kube-system/pod-kube-scheduler-kind-control-plane
        title: Access to host network
      - category: Kubernetes Security Check
        checkID: AVD-KSV-0009
        description: Sharing the host’s network namespace permits processes in the
          pod to communicate with processes bound to the host’s loopback adapter.
        messages:
        - Sharing the host’s network namespace permits processes in the pod to communicate
          with processes bound to the host’s loopback adapter.
        severity: HIGH
        success: false
        target: kube-system/pod-kube-controller-manager-kind-control-plane
        title: Access to host network
      description: Controls whether share host process namespaces
      id: "1.4"
      name: Share host process namespaces
      severity: HIGH
    - checks:
      - checkID: ""
        severity: ""
        success: true
      description: Controls whether containers can use the host network
      id: "1.5"
      name: Use the host network
      severity: HIGH
    - checks:
      - checkID: ""
        severity: ""
        success: true
      description: Controls whether container applications can run with root privileges
        or with root group membership
      id: "1.6"
      name: Run with root privileges or with root group membership
      severity: LOW
    - checks:
      - category: Kubernetes Security Check
        checkID: AVD-KSV-0001
        description: A program inside the container can elevate its own privileges
          and run as root, which might give the program control over the container
          and node.
        messages:
        - A program inside the container can elevate its own privileges and run as
          root, which might give the program control over the container and node.
        severity: MEDIUM
        success: false
        target: kube-system/pod-etcd-kind-control-plane
        title: Process can elevate its own privileges
      - category: Kubernetes Security Check
        checkID: AVD-KSV-0001
        description: A program inside the container can elevate its own privileges
          and run as root, which might give the program control over the container
          and node.
        messages:
        - A program inside the container can elevate its own privileges and run as
          root, which might give the program control over the container and node.
        severity: MEDIUM
        success: false
        target: kube-system/daemonset-kindnet
        title: Process can elevate its own privileges
      - category: Kubernetes Security Check
        checkID: AVD-KSV-0001
        description: A program inside the container can elevate its own privileges
          and run as root, which might give the program control over the container
          and node.
        messages:
        - A program inside the container can elevate its own privileges and run as
          root, which might give the program control over the container and node.
        severity: MEDIUM
        success: false
        target: kube-system/pod-kube-apiserver-kind-control-plane
        title: Process can elevate its own privileges
      - category: Kubernetes Security Check
        checkID: AVD-KSV-0001
        description: A program inside the container can elevate its own privileges
          and run as root, which might give the program control over the container
          and node.
        messages:
        - A program inside the container can elevate its own privileges and run as
          root, which might give the program control over the container and node.
        severity: MEDIUM
        success: false
        target: kube-system/daemonset-kube-proxy
        title: Process can elevate its own privileges
      - category: Kubernetes Security Check
        checkID: AVD-KSV-0001
        description: A program inside the container can elevate its own privileges
          and run as root, which might give the program control over the container
          and node.
        messages:
        - A program inside the container can elevate its own privileges and run as
          root, which might give the program control over the container and node.
        severity: MEDIUM
        success: false
        target: kube-system/pod-kube-scheduler-kind-control-plane
        title: Process can elevate its own privileges
      - category: Kubernetes Security Check
        checkID: AVD-KSV-0001
        description: A program inside the container can elevate its own privileges
          and run as root, which might give the program control over the container
          and node.
        messages:
        - A program inside the container can elevate its own privileges and run as
          root, which might give the program control over the container and node.
        severity: MEDIUM
        success: false
        target: local-path-storage/replicaset-local-path-provisioner-547f784dff
        title: Process can elevate its own privileges
      - category: Kubernetes Security Check
        checkID: AVD-KSV-0001
        description: A program inside the container can elevate its own privileges
          and run as root, which might give the program control over the container
          and node.
        messages:
        - A program inside the container can elevate its own privileges and run as
          root, which might give the program control over the container and node.
        severity: MEDIUM
        success: false
        target: kube-system/pod-kube-controller-manager-kind-control-plane
        title: Process can elevate its own privileges
      description: Control check restrictions escalation to root privileges
      id: "1.7"
      name: Restricts escalation to root privileges
      severity: MEDIUM
    - checks:
      - checkID: ""
        severity: ""
        success: true
      description: Control checks if pod sets the SELinux context of the container
      id: "1.8"
      name: Sets the SELinux context of the container
      severity: MEDIUM
    - checks:
      - category: Kubernetes Security Check
        checkID: AVD-KSV-0030
        description: The RuntimeDefault/Localhost seccomp profile must be required,
          or allow specific additional profiles.
        messages:
        - The RuntimeDefault/Localhost seccomp profile must be required, or allow
          specific additional profiles.
        severity: LOW
        success: false
        target: kube-system/pod-etcd-kind-control-plane
        title: Default Seccomp profile not set
      - category: Kubernetes Security Check
        checkID: AVD-KSV-0030
        description: The RuntimeDefault/Localhost seccomp profile must be required,
          or allow specific additional profiles.
        messages:
        - The RuntimeDefault/Localhost seccomp profile must be required, or allow
          specific additional profiles.
        severity: LOW
        success: false
        target: kube-system/replicaset-coredns-558bd4d5db
        title: Default Seccomp profile not set
      - category: Kubernetes Security Check
        checkID: AVD-KSV-0030
        description: The RuntimeDefault/Localhost seccomp profile must be required,
          or allow specific additional profiles.
        messages:
        - The RuntimeDefault/Localhost seccomp profile must be required, or allow
          specific additional profiles.
        severity: LOW
        success: false
        target: kube-system/daemonset-kindnet
        title: Default Seccomp profile not set
      - category: Kubernetes Security Check
        checkID: AVD-KSV-0030
        description: The RuntimeDefault/Localhost seccomp profile must be required,
          or allow specific additional profiles.
        messages:
        - The RuntimeDefault/Localhost seccomp profile must be required, or allow
          specific additional profiles.
        severity: LOW
        success: false
        target: kube-system/pod-kube-apiserver-kind-control-plane
        title: Default Seccomp profile not set
      - category: Kubernetes Security Check
        checkID: AVD-KSV-0030
        description: The RuntimeDefault/Localhost seccomp profile must be required,
          or allow specific additional profiles.
        messages:
        - The RuntimeDefault/Localhost seccomp profile must be required, or allow
          specific additional profiles.
        severity: LOW
        success: false
        target: kube-system/daemonset-kube-proxy
        title: Default Seccomp profile not set
      - category: Kubernetes Security Check
        checkID: AVD-KSV-0030
        description: The RuntimeDefault/Localhost seccomp profile must be required,
          or allow specific additional profiles.
        messages:
        - The RuntimeDefault/Localhost seccomp profile must be required, or allow
          specific additional profiles.
        severity: LOW
        success: false
        target: kube-system/pod-kube-scheduler-kind-control-plane
        title: Default Seccomp profile not set
      - category: Kubernetes Security Check
        checkID: AVD-KSV-0030
        description: The RuntimeDefault/Localhost seccomp profile must be required,
          or allow specific additional profiles.
        messages:
        - The RuntimeDefault/Localhost seccomp profile must be required, or allow
          specific additional profiles.
        severity: LOW
        success: false
        target: local-path-storage/replicaset-local-path-provisioner-547f784dff
        title: Default Seccomp profile not set
      - category: Kubernetes Security Check
        checkID: AVD-KSV-0030
        description: The RuntimeDefault/Localhost seccomp profile must be required,
          or allow specific additional profiles.
        messages:
        - The RuntimeDefault/Localhost seccomp profile must be required, or allow
          specific additional profiles.
        severity: LOW
        success: false
        target: kube-system/pod-kube-controller-manager-kind-control-plane
        title: Default Seccomp profile not set
      description: Control checks the restriction of containers access to resources
        with AppArmor
      id: "1.9"
      name: Restrict a container's access to resources with AppArmor
      severity: MEDIUM
    - checks:
      - category: Kubernetes Security Check
        checkID: AVD-KSV-0030
        description: The RuntimeDefault/Localhost seccomp profile must be required,
          or allow specific additional profiles.
        messages:
        - The RuntimeDefault/Localhost seccomp profile must be required, or allow
          specific additional profiles.
        severity: LOW
        success: false
        target: kube-system/pod-etcd-kind-control-plane
        title: Default Seccomp profile not set
      - category: Kubernetes Security Check
        checkID: AVD-KSV-0030
        description: The RuntimeDefault/Localhost seccomp profile must be required,
          or allow specific additional profiles.
        messages:
        - The RuntimeDefault/Localhost seccomp profile must be required, or allow
          specific additional profiles.
        severity: LOW
        success: false
        target: kube-system/replicaset-coredns-558bd4d5db
        title: Default Seccomp profile not set
      - category: Kubernetes Security Check
        checkID: AVD-KSV-0030
        description: The RuntimeDefault/Localhost seccomp profile must be required,
          or allow specific additional profiles.
        messages:
        - The RuntimeDefault/Localhost seccomp profile must be required, or allow
          specific additional profiles.
        severity: LOW
        success: false
        target: kube-system/daemonset-kindnet
        title: Default Seccomp profile not set
      - category: Kubernetes Security Check
        checkID: AVD-KSV-0030
        description: The RuntimeDefault/Localhost seccomp profile must be required,
          or allow specific additional profiles.
        messages:
        - The RuntimeDefault/Localhost seccomp profile must be required, or allow
          specific additional profiles.
        severity: LOW
        success: false
        target: kube-system/pod-kube-apiserver-kind-control-plane
        title: Default Seccomp profile not set
      - category: Kubernetes Security Check
        checkID: AVD-KSV-0030
        description: The RuntimeDefault/Localhost seccomp profile must be required,
          or allow specific additional profiles.
        messages:
        - The RuntimeDefault/Localhost seccomp profile must be required, or allow
          specific additional profiles.
        severity: LOW
        success: false
        target: kube-system/daemonset-kube-proxy
        title: Default Seccomp profile not set
      - category: Kubernetes Security Check
        checkID: AVD-KSV-0030
        description: The RuntimeDefault/Localhost seccomp profile must be required,
          or allow specific additional profiles.
        messages:
        - The RuntimeDefault/Localhost seccomp profile must be required, or allow
          specific additional profiles.
        severity: LOW
        success: false
        target: kube-system/pod-kube-scheduler-kind-control-plane
        title: Default Seccomp profile not set
      - category: Kubernetes Security Check
        checkID: AVD-KSV-0030
        description: The RuntimeDefault/Localhost seccomp profile must be required,
          or allow specific additional profiles.
        messages:
        - The RuntimeDefault/Localhost seccomp profile must be required, or allow
          specific additional profiles.
        severity: LOW
        success: false
        target: local-path-storage/replicaset-local-path-provisioner-547f784dff
        title: Default Seccomp profile not set
      - category: Kubernetes Security Check
        checkID: AVD-KSV-0030
        description: The RuntimeDefault/Localhost seccomp profile must be required,
          or allow specific additional profiles.
        messages:
        - The RuntimeDefault/Localhost seccomp profile must be required, or allow
          specific additional profiles.
        severity: LOW
        success: false
        target: kube-system/pod-kube-controller-manager-kind-control-plane
        title: Default Seccomp profile not set
      description: Control checks the sets the seccomp profile used to sandbox containers
      id: "1.10"
      name: Sets the seccomp profile used to sandbox containers.
      severity: LOW
    - checks:
      - checkID: ""
        severity: ""
        success: true
      description: 'Control check whether disable secret token been mount ,automountServiceAccountToken:
        false'
      id: "1.11"
      name: Protecting Pod service account tokens
      severity: MEDIUM
    - checks:
      - category: Kubernetes Security Check
        checkID: AVD-KSV-0037
        description: ensure that User pods are not placed in kube-system namespace
        messages:
        - ensure that User pods are not placed in kube-system namespace
        severity: MEDIUM
        success: false
        target: kube-system/replicaset-coredns-558bd4d5db
        title: User Pods should not be placed in kube-system namespace
      - category: Kubernetes Security Check
        checkID: AVD-KSV-0037
        description: ensure that User pods are not placed in kube-system namespace
        messages:
        - ensure that User pods are not placed in kube-system namespace
        severity: MEDIUM
        success: false
        target: kube-system/service-kube-dns
        title: User Pods should not be placed in kube-system namespace
      - category: Kubernetes Security Check
        checkID: AVD-KSV-0037
        description: ensure that User pods are not placed in kube-system namespace
        messages:
        - ensure that User pods are not placed in kube-system namespace
        severity: MEDIUM
        success: false
        target: kube-system/daemonset-kindnet
        title: User Pods should not be placed in kube-system namespace
      - category: Kubernetes Security Check
        checkID: AVD-KSV-0037
        description: ensure that User pods are not placed in kube-system namespace
        messages:
        - ensure that User pods are not placed in kube-system namespace
        severity: MEDIUM
        success: false
        target: kube-system/daemonset-kube-proxy
        title: User Pods should not be placed in kube-system namespace
      description: Control check whether Namespace kube-system is not be used by users
      id: "1.12"
      name: Namespace kube-system should not be used by users
      severity: MEDIUM
      status: FAIL
    - checks:
      - checkID: ""
        severity: ""
        success: true
      description: Control check validate the pod and/or namespace Selectors usage
      id: "2.0"
      name: Pod and/or namespace Selectors usage
      severity: MEDIUM
      status: FAIL
    - checks:
      - checkID: ""
        severity: ""
        success: true
      description: Control check whether check cni plugin installed
      id: "3.0"
      name: Use CNI plugin that supports NetworkPolicy API (Manual)
      severity: CRITICAL
      status: FAIL
    - checks:
      - checkID: ""
        severity: ""
        success: true
      description: Control check the use of ResourceQuota policy to limit aggregate
        resource usage within namespace
      id: "4.0"
      name: Use ResourceQuota policies to limit resources
      severity: MEDIUM
      status: FAIL
    - checks:
      - checkID: ""
        severity: ""
        success: true
      description: Control check the use of LimitRange policy limit resource usage
        for namespaces or nodes
      id: "4.1"
      name: Use LimitRange policies to limit resources
      severity: MEDIUM
      status: FAIL
    - checks:
      - checkID: ""
        severity: ""
        success: true
      description: Control check whether control plan disable insecure port
      id: "5.0"
      name: Control plan disable insecure port (Manual)
      severity: CRITICAL
      status: FAIL
    - checks:
      - checkID: ""
        severity: ""
        success: true
      description: Control check whether etcd communication is encrypted
      id: "5.1"
      name: Encrypt etcd communication
      severity: CRITICAL
    - checks:
      - checkID: ""
        severity: ""
        success: true
      description: Control check whether kube config file permissions
      id: "6.0"
      name: Ensure kube config file permission (Manual)
      severity: CRITICAL
      status: FAIL
    - checks:
      - category: Kubernetes Security Check
        checkID: AVD-KCV-0029
        description: etcd should be configured to make use of TLS encryption for client
          connections.
        messages:
        - etcd should be configured to make use of TLS encryption for client connections.
        severity: LOW
        success: false
        target: kube-system/pod-kube-apiserver-kind-control-plane
        title: Ensure that the --etcd-cafile argument is set as appropriate
      description: Control checks whether encryption resource has been set
      id: "6.1"
      name: Check that encryption resource has been set
      severity: CRITICAL
    - checks:
      - checkID: ""
        severity: ""
        success: true
      description: Control checks whether encryption provider has been set
      id: "6.2"
      name: Check encryption provider
      severity: CRITICAL
    - checks:
      - category: Kubernetes Security Check
        checkID: AVD-KCV-0001
        description: Disable anonymous requests to the API server.
        messages:
        - Disable anonymous requests to the API server.
        severity: MEDIUM
        success: false
        target: kube-system/pod-kube-apiserver-kind-control-plane
        title: Ensure that the --anonymous-auth argument is set to false
      description: Control checks whether anonymous-auth is unset
      id: "7.0"
      name: Make sure anonymous-auth is unset
      severity: CRITICAL
    - checks:
      - checkID: ""
        severity: ""
        success: true
      description: Control check whether RBAC permission is in use
      id: "7.1"
      name: Make sure -authorization-mode=RBAC
      severity: CRITICAL
    - checks:
      - checkID: ""
        severity: ""
        success: true
      description: Control check whether audit policy is configure
      id: "8.0"
      name: Audit policy is configure (Manual)
      severity: HIGH
      status: FAIL
    - checks:
      - category: Kubernetes Security Check
        checkID: AVD-KCV-0019
        description: Enable auditing on the Kubernetes API Server and set the desired
          audit log path.
        messages:
        - Enable auditing on the Kubernetes API Server and set the desired audit log
          path.
        severity: LOW
        success: false
        target: kube-system/pod-kube-apiserver-kind-control-plane
        title: Ensure that the --audit-log-path argument is set
      description: Control check whether audit log path is configure
      id: "8.1"
      name: Audit log path is configure
      severity: MEDIUM
    - checks:
      - category: Kubernetes Security Check
        checkID: AVD-KCV-0020
        description: Retain the logs for at least 30 days or as appropriate.
        messages:
        - Retain the logs for at least 30 days or as appropriate.
        severity: LOW
        success: false
        target: kube-system/pod-kube-apiserver-kind-control-plane
        title: Ensure that the --audit-log-maxage argument is set to 30 or as appropriate
      description: Control check whether audit log aging is configure
      id: "8.2"
      name: Audit log aging
      severity: MEDIUM
    title: nsa
    version: "1.0"
  totalCounts:
    failCount: 12
    passCount: 15
  updateTimestamp: "2022-12-05T08:43:10Z"
```

</details>

<details>

<summary>Kubernetes CIS Benchmark 1.23</summary>

```json
{
    "apiVersion": "aquasecurity.github.io/v1alpha1",
    "kind": "ClusterComplianceReport",
    "metadata": {
        "creationTimestamp": "2023-01-01T10:27:01Z",
        "generation": 1,
        "labels": {
            "app.kubernetes.io/instance": "trivy-operator",
            "app.kubernetes.io/managed-by": "kubectl",
            "app.kubernetes.io/name": "trivy-operator",
            "app.kubernetes.io/version": "0.18.0-rc"
        },
        "name": "cis",
        "resourceVersion": "8985",
        "uid": "698f0de6-16dd-410c-b102-9cb068bc5c0d"
    },
    "spec": {
        "compliance": {
            "controls": [
                {
                    "checks": [
                        {
                            "id": "AVD-KCV-0001"
                        }
                    ],
                    "description": "Disable anonymous requests to the API server",
                    "id": "1.2.1",
                    "name": "Ensure that the --anonymous-auth argument is set to false",
                    "severity": "MEDIUM"
                },
                {
                    "checks": [
                        {
                            "id": "AVD-KCV-0002"
                        }
                    ],
                    "description": "Do not use token based authentication.",
                    "id": "1.2.2",
                    "name": "Ensure that the --token-auth-file parameter is not set",
                    "severity": "LOW"
                },
                {
                    "checks": [
                        {
                            "id": "AVD-KCV-0003"
                        }
                    ],
                    "description": "This admission controller rejects all net-new usage of the Service field externalIPs.",
                    "id": "1.2.3",
                    "name": "Ensure that the --DenyServiceExternalIPs is not set",
                    "severity": "LOW"
                },
                {
                    "checks": [
                        {
                            "id": "AVD-KCV-0004"
                        }
                    ],
                    "description": "Use https for kubelet connections.",
                    "id": "1.2.4",
                    "name": "Ensure that the --kubelet-https argument is set to true",
                    "severity": "LOW"
                },
                {
                    "checks": [
                        {
                            "id": "AVD-KCV-0005"
                        }
                    ],
                    "description": "Enable certificate based kubelet authentication.",
                    "id": "1.2.5",
                    "name": "Ensure that the --kubelet-client-certificate and --kubelet-client-key arguments are set as appropriate",
                    "severity": "HIGH"
                },
                {
                    "checks": [
                        {
                            "id": "AVD-KCV-0006"
                        }
                    ],
                    "description": "Verify kubelets certificate before establishing connection.",
                    "id": "1.2.6",
                    "name": "Ensure that the --kubelet-certificate-authority argument is set as appropriate",
                    "severity": "HIGH"
                },
                {
                    "checks": [
                        {
                            "id": "AVD-KCV-0007"
                        }
                    ],
                    "description": "Do not always authorize all requests.",
                    "id": "1.2.7",
                    "name": "Ensure that the --authorization-mode argument is not set to AlwaysAllow",
                    "severity": "LOW"
                },
                {
                    "checks": [
                        {
                            "id": "AVD-KCV-0008"
                        }
                    ],
                    "description": "Restrict kubelet nodes to reading only objects associated with them.",
                    "id": "1.2.8",
                    "name": "Ensure that the --authorization-mode argument includes Node",
                    "severity": "HIGH"
                },
                {
                    "checks": [
                        {
                            "id": "AVD-KCV-0009"
                        }
                    ],
                    "description": "Turn on Role Based Access Control.",
                    "id": "1.2.9",
                    "name": "Ensure that the --authorization-mode argument includes RBAC",
                    "severity": "HIGH"
                },
                {
                    "checks": [
                        {
                            "id": "AVD-KCV-0010"
                        }
                    ],
                    "description": "Limit the rate at which the API server accepts requests.",
                    "id": "1.2.10",
                    "name": "Ensure that the admission control plugin EventRateLimit is set",
                    "severity": "HIGH"
                },
                {
                    "checks": [
                        {
                            "id": "AVD-KCV-0011"
                        }
                    ],
                    "description": "Do not allow all requests",
                    "id": "1.2.11",
                    "name": "Ensure that the admission control plugin AlwaysAdmit is not set",
                    "severity": "LOW"
                },
                {
                    "checks": [
                        {
                            "id": "AVD-KCV-0012"
                        }
                    ],
                    "description": "Always pull images",
                    "id": "1.2.12",
                    "name": "Ensure that the admission control plugin AlwaysPullImages is set",
                    "severity": "MEDIUM"
                },
                {
                    "checks": [
                        {
                            "id": "AVD-KCV-0013"
                        }
                    ],
                    "description": "The SecurityContextDeny admission controller can be used to deny pods which make use of some SecurityContext fields which could allow for privilege escalation in the cluster. This should be used where PodSecurityPolicy is not in place within the cluster.",
                    "id": "1.2.13",
                    "name": "Ensure that the admission control plugin SecurityContextDeny is set if PodSecurityPolicy is not used",
                    "severity": "MEDIUM"
                },
                {
                    "checks": [
                        {
                            "id": "AVD-KCV-0014"
                        }
                    ],
                    "description": "Automate service accounts management.",
                    "id": "1.2.14",
                    "name": "Ensure that the admission control plugin ServiceAccount is set",
                    "severity": "LOW"
                },
                {
                    "checks": [
                        {
                            "id": "AVD-KCV-0015"
                        }
                    ],
                    "description": "Reject creating objects in a namespace that is undergoing termination.",
                    "id": "1.2.15",
                    "name": "Ensure that the admission control plugin NamespaceLifecycle is set",
                    "severity": "LOW"
                },
                {
                    "checks": [
                        {
                            "id": "AVD-KCV-0016"
                        }
                    ],
                    "description": "Limit the Node and Pod objects that a kubelet could modify.",
                    "id": "1.2.16",
                    "name": "Ensure that the admission control plugin NodeRestriction is set",
                    "severity": "LOW"
                },
                {
                    "checks": [
                        {
                            "id": "AVD-KCV-0017"
                        }
                    ],
                    "description": "Do not disable the secure port",
                    "id": "1.2.17",
                    "name": "Ensure that the --secure-port argument is not set to 0",
                    "severity": "HIGH"
                },
                {
                    "checks": [
                        {
                            "id": "AVD-KCV-0018"
                        }
                    ],
                    "description": "Disable profiling, if not needed.",
                    "id": "1.2.18",
                    "name": "Ensure that the --profiling argument is set to false",
                    "severity": "LOW"
                },
                {
                    "checks": [
                        {
                            "id": "AVD-KCV-0019"
                        }
                    ],
                    "description": "Enable auditing on the Kubernetes API Server and set the desired audit log path.",
                    "id": "1.2.19",
                    "name": "Ensure that the --audit-log-path argument is set",
                    "severity": "LOW"
                },
                {
                    "checks": [
                        {
                            "id": "AVD-KCV-0020"
                        }
                    ],
                    "description": "Retain the logs for at least 30 days or as appropriate.",
                    "id": "1.2.20",
                    "name": "Ensure that the --audit-log-maxage argument is set to 30 or as appropriate",
                    "severity": "LOW"
                },
                {
                    "checks": [
                        {
                            "id": "AVD-KCV-0021"
                        }
                    ],
                    "description": "Retain 10 or an appropriate number of old log file.",
                    "id": "1.2.21",
                    "name": "Ensure that the --audit-log-maxbackup argument is set to 10 or as appropriate",
                    "severity": "LOW"
                },
                {
                    "checks": [
                        {
                            "id": "AVD-KCV-0022"
                        }
                    ],
                    "description": "Rotate log files on reaching 100 MB or as appropriate.",
                    "id": "1.2.22",
                    "name": "Ensure that the --audit-log-maxsize argument is set to 100 or as appropriate",
                    "severity": "LOW"
                },
                {
                    "checks": [
                        {
                            "id": "AVD-KCV-0024"
                        }
                    ],
                    "description": "Validate service account before validating token.",
                    "id": "1.2.24",
                    "name": "Ensure that the --service-account-lookup argument is set to true",
                    "severity": "LOW"
                },
                {
                    "checks": [
                        {
                            "id": "AVD-KCV-0025"
                        }
                    ],
                    "description": "Explicitly set a service account public key file for service accounts on the apiserver.",
                    "id": "1.2.25",
                    "name": "Ensure that the --service-account-key-file argument is set as appropriate",
                    "severity": "LOW"
                },
                {
                    "checks": [
                        {
                            "id": "AVD-KCV-0026"
                        }
                    ],
                    "description": "etcd should be configured to make use of TLS encryption for client connections.",
                    "id": "1.2.26",
                    "name": "Ensure that the --etcd-certfile and --etcd-keyfile arguments are set as appropriate",
                    "severity": "LOW"
                },
                {
                    "checks": [
                        {
                            "id": "AVD-KCV-0027"
                        }
                    ],
                    "description": "Setup TLS connection on the API server.",
                    "id": "1.2.27",
                    "name": "Ensure that the --tls-cert-file and --tls-private-key-file arguments are set as appropriate",
                    "severity": "MEDIUM"
                },
                {
                    "checks": [
                        {
                            "id": "AVD-KCV-0028"
                        }
                    ],
                    "description": "Setup TLS connection on the API server.",
                    "id": "1.2.28",
                    "name": "Ensure that the --client-ca-file argument is set appropriate",
                    "severity": "LOW"
                },
                {
                    "checks": [
                        {
                            "id": "AVD-KCV-0029"
                        }
                    ],
                    "description": "etcd should be configured to make use of TLS encryption for client connections.",
                    "id": "1.2.29",
                    "name": "Ensure that the --etcd-cafile argument is set as appropriate",
                    "severity": "LOW"
                },
                {
                    "checks": [
                        {
                            "id": "AVD-KCV-0030"
                        }
                    ],
                    "description": "Encrypt etcd key-value store.",
                    "id": "1.2.30",
                    "name": "Ensure that the --encryption-provider-config argument is set as appropriate",
                    "severity": "LOW"
                },
                {
                    "checks": [
                        {
                            "id": "AVD-KCV-0033"
                        }
                    ],
                    "description": "Activate garbage collector on pod termination, as appropriate.",
                    "id": "1.3.1",
                    "name": "Ensure that the --terminated-pod-gc-threshold argument is set as appropriate",
                    "severity": "MEDIUM"
                },
                {
                    "checks": [
                        {
                            "id": "AVD-KCV-0035"
                        }
                    ],
                    "description": "Use individual service account credentials for each controller.",
                    "id": "1.3.3",
                    "name": "Ensure that the --use-service-account-credentials argument is set to true",
                    "severity": "MEDIUM"
                },
                {
                    "checks": [
                        {
                            "id": "AVD-KCV-0036"
                        }
                    ],
                    "description": "Explicitly set a service account private key file for service accounts on the controller manager.",
                    "id": "1.3.4",
                    "name": "Ensure that the --service-account-private-key-file argument is set as appropriate",
                    "severity": "MEDIUM"
                },
                {
                    "checks": [
                        {
                            "id": "AVD-KCV-0037"
                        }
                    ],
                    "description": "Allow pods to verify the API servers serving certificate before establishing connections.",
                    "id": "1.3.5",
                    "name": "Ensure that the --root-ca-file argument is set as appropriate",
                    "severity": "MEDIUM"
                },
                {
                    "checks": [
                        {
                            "id": "AVD-KCV-0038"
                        }
                    ],
                    "description": "Enable kubelet server certificate rotation on controller-manager.",
                    "id": "1.3.6",
                    "name": "Ensure that the RotateKubeletServerCertificate argument is set to true",
                    "severity": "MEDIUM"
                },
                {
                    "checks": [
                        {
                            "id": "AVD-KCV-0039"
                        }
                    ],
                    "description": "Do not bind the scheduler service to non-loopback insecure addresses.",
                    "id": "1.3.7",
                    "name": "Ensure that the --bind-address argument is set to 127.0.0.1",
                    "severity": "LOW"
                },
                {
                    "checks": [
                        {
                            "id": "AVD-KCV-0034"
                        }
                    ],
                    "description": "Disable profiling, if not needed.",
                    "id": "1.4.1",
                    "name": "Ensure that the --profiling argument is set to false",
                    "severity": "MEDIUM"
                },
                {
                    "checks": [
                        {
                            "id": "AVD-KCV-0041"
                        }
                    ],
                    "description": "Do not bind the scheduler service to non-loopback insecure addresses.",
                    "id": "1.4.2",
                    "name": "Ensure that the --bind-address argument is set to 127.0.0.1",
                    "severity": "CRITICAL"
                },
                {
                    "checks": [
                        {
                            "id": "AVD-KCV-0042"
                        }
                    ],
                    "description": "Configure TLS encryption for the etcd service.",
                    "id": "2.1",
                    "name": "Ensure that the --cert-file and --key-file arguments are set as appropriate",
                    "severity": "MEDIUM"
                },
                {
                    "checks": [
                        {
                            "id": "AVD-KCV-0043"
                        }
                    ],
                    "description": "Enable client authentication on etcd service.",
                    "id": "2.2",
                    "name": "Ensure that the --client-cert-auth argument is set to true",
                    "severity": "CRITICAL"
                },
                {
                    "checks": [
                        {
                            "id": "AVD-KCV-0044"
                        }
                    ],
                    "description": "Do not use self-signed certificates for TLS.",
                    "id": "2.3",
                    "name": "Ensure that the --auto-tls argument is not set to true",
                    "severity": "CRITICAL"
                },
                {
                    "checks": [
                        {
                            "id": "AVD-KCV-0045"
                        }
                    ],
                    "description": "etcd should be configured to make use of TLS encryption for peer connections.",
                    "id": "2.4",
                    "name": "Ensure that the --peer-cert-file and --peer-key-file arguments are set as appropriate",
                    "severity": "CRITICAL"
                },
                {
                    "checks": [
                        {
                            "id": "AVD-KCV-0046"
                        }
                    ],
                    "description": "etcd should be configured for peer authentication.",
                    "id": "2.5",
                    "name": "Ensure that the --peer-client-cert-auth argument is set to true",
                    "severity": "CRITICAL"
                },
                {
                    "checks": [
                        {
                            "id": "AVD-KCV-0047"
                        }
                    ],
                    "description": "Do not use self-signed certificates for TLS.",
                    "id": "2.6",
                    "name": "Ensure that the --peer-auto-tls argument is not set to true",
                    "severity": "HIGH"
                },
                {
                    "description": "Kubernetes provides the option to use client certificates for user authentication. However as there is no way to revoke these certificates when a user leaves an organization or loses their credential, they are not suitable for this purpose.",
                    "id": "3.1.1",
                    "name": "Client certificate authentication should not be used for users (Manual)",
                    "severity": "HIGH"
                },
                {
                    "description": "Kubernetes can audit the details of requests made to the API server. The --audit- policy-file flag must be set for this logging to be enabled.",
                    "id": "3.2.1",
                    "name": "Ensure that a minimal audit policy is created (Manual)",
                    "severity": "HIGH"
                },
                {
                    "description": "Ensure that the audit policy created for the cluster covers key security concerns.",
                    "id": "3.2.2",
                    "name": "Ensure that the audit policy covers key security concerns (Manual)",
                    "severity": "HIGH"
                },
                {
                    "checks": [
                        {
                            "id": "AVD-KSV-0111"
                        }
                    ],
                    "description": "The RBAC role cluster-admin provides wide-ranging powers over the environment and should be used only where and when needed.",
                    "id": "5.1.1",
                    "name": "Ensure that the cluster-admin role is only used where required",
                    "severity": "HIGH"
                },
                {
                    "checks": [
                        {
                            "id": "AVD-KSV-0041"
                        }
                    ],
                    "description": "The Kubernetes API stores secrets, which may be service account tokens for the Kubernetes API or credentials used by workloads in the cluster",
                    "id": "5.1.2",
                    "name": "Minimize access to secrets",
                    "severity": "HIGH"
                },
                {
                    "checks": [
                        {
                            "id": "AVD-KSV-0044"
                        },
                        {
                            "id": "AVD-KSV-0045"
                        },
                        {
                            "id": "AVD-KSV-0046"
                        }
                    ],
                    "description": "Kubernetes Roles and ClusterRoles provide access to resources based on sets of objects and actions that can be taken on those objects. It is possible to set either of these to be the wildcard \"*\" which matches all items",
                    "id": "5.1.3",
                    "name": "Minimize wildcard use in Roles and ClusterRoles",
                    "severity": "HIGH"
                },
                {
                    "checks": [
                        {
                            "id": "AVD-KSV-0036"
                        }
                    ],
                    "description": "Service accounts tokens should not be mounted in pods except where the workload running in the pod explicitly needs to communicate with the API server",
                    "id": "5.1.6",
                    "name": "Ensure that Service Account Tokens are only mounted where necessary",
                    "severity": "HIGH"
                },
                {
                    "checks": [
                        {
                            "id": "AVD-KSV-0043"
                        }
                    ],
                    "description": "Cluster roles and roles with the impersonate, bind or escalate permissions should not be granted unless strictly required",
                    "id": "5.1.8",
                    "name": "Limit use of the Bind, Impersonate and Escalate permissions in the Kubernetes cluster",
                    "severity": "HIGH"
                },
                {
                    "checks": [
                        {
                            "id": "AVD-KSV-0017"
                        }
                    ],
                    "description": "Do not generally permit containers to be run with the securityContext.privileged flag set to true.",
                    "id": "5.2.2",
                    "name": "Minimize the admission of privileged containers",
                    "severity": "HIGH"
                },
                {
                    "checks": [
                        {
                            "id": "AVD-KSV-0010"
                        }
                    ],
                    "description": "Do not generally permit containers to be run with the hostPID flag set to true.",
                    "id": "5.2.3",
                    "name": "Minimize the admission of containers wishing to share the host process ID namespace",
                    "severity": "HIGH"
                },
                {
                    "checks": [
                        {
                            "id": "AVD-KSV-0008"
                        }
                    ],
                    "description": "Do not generally permit containers to be run with the hostIPC flag set to true.",
                    "id": "5.2.4",
                    "name": "Minimize the admission of containers wishing to share the host IPC namespace",
                    "severity": "HIGH"
                },
                {
                    "checks": [
                        {
                            "id": "AVD-KSV-0009"
                        }
                    ],
                    "description": "Do not generally permit containers to be run with the hostNetwork flag set to true.",
                    "id": "5.2.5",
                    "name": "Minimize the admission of containers wishing to share the host network namespace",
                    "severity": "HIGH"
                },
                {
                    "checks": [
                        {
                            "id": "AVD-KSV-0001"
                        }
                    ],
                    "description": "Do not generally permit containers to be run with the allowPrivilegeEscalation flag set to true",
                    "id": "5.2.6",
                    "name": "Minimize the admission of containers with allowPrivilegeEscalation",
                    "severity": "HIGH"
                },
                {
                    "checks": [
                        {
                            "id": "AVD-KSV-0012"
                        }
                    ],
                    "description": "Do not generally permit containers to be run as the root user.",
                    "id": "5.2.7",
                    "name": "Minimize the admission of root containers",
                    "severity": "MEDIUM"
                },
                {
                    "checks": [
                        {
                            "id": "AVD-KSV-0022"
                        }
                    ],
                    "description": "Do not generally permit containers with the potentially dangerous NET_RAW capability.",
                    "id": "5.2.8",
                    "name": "Minimize the admission of containers with the NET_RAW capability",
                    "severity": "MEDIUM"
                },
                {
                    "checks": [
                        {
                            "id": "AVD-KSV-0004"
                        }
                    ],
                    "description": "Do not generally permit containers with capabilities assigned beyond the default set.",
                    "id": "5.2.9",
                    "name": "Minimize the admission of containers with added capabilities",
                    "severity": "LOW"
                },
                {
                    "checks": [
                        {
                            "id": "AVD-KSV-0003"
                        }
                    ],
                    "description": "Do not generally permit containers with capabilities",
                    "id": "5.2.10",
                    "name": "Minimize the admission of containers with capabilities assigned",
                    "severity": "LOW"
                },
                {
                    "checks": [
                        {
                            "id": "AVD-KSV-0103"
                        }
                    ],
                    "description": "Do not generally permit containers with capabilities",
                    "id": "5.2.11",
                    "name": "Minimize the admission of containers with capabilities assigned",
                    "severity": "MEDIUM"
                },
                {
                    "checks": [
                        {
                            "id": "AVD-KSV-0023"
                        }
                    ],
                    "description": "Do not generally admit containers which make use of hostPath volumes.",
                    "id": "5.2.12",
                    "name": "Minimize the admission of HostPath volumes",
                    "severity": "MEDIUM"
                },
                {
                    "checks": [
                        {
                            "id": "AVD-KSV-0024"
                        }
                    ],
                    "description": "Do not generally permit containers which require the use of HostPorts.",
                    "id": "5.2.13",
                    "name": "Minimize the admission of containers which use HostPorts",
                    "severity": "MEDIUM"
                },
                {
                    "description": "There are a variety of CNI plugins available for Kubernetes. If the CNI in use does not support Network Policies it may not be possible to effectively restrict traffic in the cluster.",
                    "id": "5.3.1",
                    "name": "Ensure that the CNI in use supports Network Policies (Manual)",
                    "severity": "MEDIUM"
                },
                {
                    "checks": [
                        {
                            "id": "AVD-KSV-0038"
                        }
                    ],
                    "description": "Use network policies to isolate traffic in your cluster network.",
                    "id": "5.3.2",
                    "name": "Ensure that all Namespaces have Network Policies defined",
                    "severity": "MEDIUM"
                },
                {
                    "description": "Kubernetes supports mounting secrets as data volumes or as environment variables. Minimize the use of environment variable secrets.",
                    "id": "5.4.1",
                    "name": "Prefer using secrets as files over secrets as environment variables (Manual)",
                    "severity": "MEDIUM"
                },
                {
                    "description": "Consider the use of an external secrets storage and management system, instead of using Kubernetes Secrets directly, if you have more complex secret management needs.",
                    "id": "5.4.2",
                    "name": "Consider external secret storage (Manual)",
                    "severity": "MEDIUM"
                },
                {
                    "description": "Configure Image Provenance for your deployment.",
                    "id": "5.5.1",
                    "name": "Configure Image Provenance using ImagePolicyWebhook admission controller (Manual)",
                    "severity": "MEDIUM"
                },
                {
                    "description": "Use namespaces to isolate your Kubernetes objects.",
                    "id": "5.7.1",
                    "name": "Create administrative boundaries between resources using namespaces (Manual)",
                    "severity": "MEDIUM"
                },
                {
                    "checks": [
                        {
                            "id": "AVD-KSV-0104"
                        }
                    ],
                    "description": "Enable docker/default seccomp profile in your pod definitions.",
                    "id": "5.7.2",
                    "name": "Ensure that the seccomp profile is set to docker/default in your pod definitions",
                    "severity": "MEDIUM"
                },
                {
                    "checks": [
                        {
                            "id": "AVD-KSV-0021"
                        },
                        {
                            "id": "AVD-KSV-0020"
                        },
                        {
                            "id": "AVD-KSV-0005"
                        },
                        {
                            "id": "AVD-KSV-0025"
                        },
                        {
                            "id": "AVD-KSV-0104"
                        },
                        {
                            "id": "AVD-KSV-0030"
                        }
                    ],
                    "description": "Apply Security Context to Your Pods and Containers",
                    "id": "5.7.3",
                    "name": "Apply Security Context to Your Pods and Containers",
                    "severity": "HIGH"
                },
                {
                    "checks": [
                        {
                            "id": "AVD-KSV-0110"
                        }
                    ],
                    "description": "Kubernetes provides a default namespace, where objects are placed if no namespace is specified for them",
                    "id": "5.7.4",
                    "name": "The default namespace should not be used",
                    "severity": "MEDIUM"
                }
            ],
            "description": "CIS Kubernetes Benchmarks",
            "id": "cis",
            "relatedResources": [
                "https://www.cisecurity.org/benchmark/kubernetes"
            ],
            "title": "CIS Kubernetes Benchmarks v1.23",
            "version": "1.0"
        },
        "cron": "** ** *",
        "reportType": "summary"
    },
    "status": {
        "summary": {
            "failCount": 24,
            "passCount": 48
        },
        "summaryReport": {
            "controlCheck": [
                {
                    "id": "1.2.1",
                    "name": "Ensure that the --anonymous-auth argument is set to false",
                    "severity": "MEDIUM",
                    "totalFail": 1
                },
                {
                    "id": "1.2.2",
                    "name": "Ensure that the --token-auth-file parameter is not set",
                    "severity": "LOW",
                    "totalFail": 0
                },
                {
                    "id": "1.2.3",
                    "name": "Ensure that the --DenyServiceExternalIPs is not set",
                    "severity": "LOW",
                    "totalFail": 0
                },
                {
                    "id": "1.2.4",
                    "name": "Ensure that the --kubelet-https argument is set to true",
                    "severity": "LOW",
                    "totalFail": 0
                },
                {
                    "id": "1.2.5",
                    "name": "Ensure that the --kubelet-client-certificate and --kubelet-client-key arguments are set as appropriate",
                    "severity": "HIGH",
                    "totalFail": 0
                },
                {
                    "id": "1.2.6",
                    "name": "Ensure that the --kubelet-certificate-authority argument is set as appropriate",
                    "severity": "HIGH",
                    "totalFail": 1
                },
                {
                    "id": "1.2.7",
                    "name": "Ensure that the --authorization-mode argument is not set to AlwaysAllow",
                    "severity": "LOW",
                    "totalFail": 0
                },
                {
                    "id": "1.2.8",
                    "name": "Ensure that the --authorization-mode argument includes Node",
                    "severity": "HIGH",
                    "totalFail": 0
                },
                {
                    "id": "1.2.9",
                    "name": "Ensure that the --authorization-mode argument includes RBAC",
                    "severity": "HIGH",
                    "totalFail": 0
                },
                {
                    "id": "1.2.10",
                    "name": "Ensure that the admission control plugin EventRateLimit is set",
                    "severity": "HIGH",
                    "totalFail": 1
                },
                {
                    "id": "1.2.11",
                    "name": "Ensure that the admission control plugin AlwaysAdmit is not set",
                    "severity": "LOW",
                    "totalFail": 0
                },
                {
                    "id": "1.2.12",
                    "name": "Ensure that the admission control plugin AlwaysPullImages is set",
                    "severity": "MEDIUM",
                    "totalFail": 0
                },
                {
                    "id": "1.2.13",
                    "name": "Ensure that the admission control plugin SecurityContextDeny is set if PodSecurityPolicy is not used",
                    "severity": "MEDIUM",
                    "totalFail": 1
                },
                {
                    "id": "1.2.14",
                    "name": "Ensure that the admission control plugin ServiceAccount is set",
                    "severity": "LOW",
                    "totalFail": 0
                },
                {
                    "id": "1.2.15",
                    "name": "Ensure that the admission control plugin NamespaceLifecycle is set",
                    "severity": "LOW",
                    "totalFail": 0
                },
                {
                    "id": "1.2.16",
                    "name": "Ensure that the admission control plugin NodeRestriction is set",
                    "severity": "LOW",
                    "totalFail": 0
                },
                {
                    "id": "1.2.17",
                    "name": "Ensure that the --secure-port argument is not set to 0",
                    "severity": "HIGH",
                    "totalFail": 0
                },
                {
                    "id": "1.2.18",
                    "name": "Ensure that the --profiling argument is set to false",
                    "severity": "LOW",
                    "totalFail": 1
                },
                {
                    "id": "1.2.19",
                    "name": "Ensure that the --audit-log-path argument is set",
                    "severity": "LOW",
                    "totalFail": 1
                },
                {
                    "id": "1.2.20",
                    "name": "Ensure that the --audit-log-maxage argument is set to 30 or as appropriate",
                    "severity": "LOW",
                    "totalFail": 1
                },
                {
                    "id": "1.2.21",
                    "name": "Ensure that the --audit-log-maxbackup argument is set to 10 or as appropriate",
                    "severity": "LOW",
                    "totalFail": 1
                },
                {
                    "id": "1.2.22",
                    "name": "Ensure that the --audit-log-maxsize argument is set to 100 or as appropriate",
                    "severity": "LOW",
                    "totalFail": 1
                },
                {
                    "id": "1.2.24",
                    "name": "Ensure that the --service-account-lookup argument is set to true",
                    "severity": "LOW",
                    "totalFail": 0
                },
                {
                    "id": "1.2.25",
                    "name": "Ensure that the --service-account-key-file argument is set as appropriate",
                    "severity": "LOW",
                    "totalFail": 0
                },
                {
                    "id": "1.2.26",
                    "name": "Ensure that the --etcd-certfile and --etcd-keyfile arguments are set as appropriate",
                    "severity": "LOW",
                    "totalFail": 0
                },
                {
                    "id": "1.2.27",
                    "name": "Ensure that the --tls-cert-file and --tls-private-key-file arguments are set as appropriate",
                    "severity": "MEDIUM",
                    "totalFail": 0
                },
                {
                    "id": "1.2.28",
                    "name": "Ensure that the --client-ca-file argument is set appropriate",
                    "severity": "LOW",
                    "totalFail": 1
                },
                {
                    "id": "1.2.29",
                    "name": "Ensure that the --etcd-cafile argument is set as appropriate",
                    "severity": "LOW",
                    "totalFail": 1
                },
                {
                    "id": "1.2.30",
                    "name": "Ensure that the --encryption-provider-config argument is set as appropriate",
                    "severity": "LOW",
                    "totalFail": 0
                },
                {
                    "id": "1.3.1",
                    "name": "Ensure that the --terminated-pod-gc-threshold argument is set as appropriate",
                    "severity": "MEDIUM",
                    "totalFail": 1
                },
                {
                    "id": "1.3.3",
                    "name": "Ensure that the --use-service-account-credentials argument is set to true",
                    "severity": "MEDIUM",
                    "totalFail": 0
                },
                {
                    "id": "1.3.4",
                    "name": "Ensure that the --service-account-private-key-file argument is set as appropriate",
                    "severity": "MEDIUM",
                    "totalFail": 0
                },
                {
                    "id": "1.3.5",
                    "name": "Ensure that the --root-ca-file argument is set as appropriate",
                    "severity": "MEDIUM",
                    "totalFail": 0
                },
                {
                    "id": "1.3.6",
                    "name": "Ensure that the RotateKubeletServerCertificate argument is set to true",
                    "severity": "MEDIUM",
                    "totalFail": 1
                },
                {
                    "id": "1.3.7",
                    "name": "Ensure that the --bind-address argument is set to 127.0.0.1",
                    "severity": "LOW",
                    "totalFail": 0
                },
                {
                    "id": "1.4.1",
                    "name": "Ensure that the --profiling argument is set to false",
                    "severity": "MEDIUM",
                    "totalFail": 1
                },
                {
                    "id": "1.4.2",
                    "name": "Ensure that the --bind-address argument is set to 127.0.0.1",
                    "severity": "CRITICAL",
                    "totalFail": 0
                },
                {
                    "id": "2.1",
                    "name": "Ensure that the --cert-file and --key-file arguments are set as appropriate",
                    "severity": "MEDIUM",
                    "totalFail": 0
                },
                {
                    "id": "2.2",
                    "name": "Ensure that the --client-cert-auth argument is set to true",
                    "severity": "CRITICAL",
                    "totalFail": 0
                },
                {
                    "id": "2.3",
                    "name": "Ensure that the --auto-tls argument is not set to true",
                    "severity": "CRITICAL",
                    "totalFail": 0
                },
                {
                    "id": "2.4",
                    "name": "Ensure that the --peer-cert-file and --peer-key-file arguments are set as appropriate",
                    "severity": "CRITICAL",
                    "totalFail": 0
                },
                {
                    "id": "2.5",
                    "name": "Ensure that the --peer-client-cert-auth argument is set to true",
                    "severity": "CRITICAL",
                    "totalFail": 0
                },
                {
                    "id": "2.6",
                    "name": "Ensure that the --peer-auto-tls argument is not set to true",
                    "severity": "HIGH",
                    "totalFail": 0
                },
                {
                    "id": "3.1.1",
                    "name": "Client certificate authentication should not be used for users (Manual)",
                    "severity": "HIGH"
                },
                {
                    "id": "3.2.1",
                    "name": "Ensure that a minimal audit policy is created (Manual)",
                    "severity": "HIGH"
                },
                {
                    "id": "3.2.2",
                    "name": "Ensure that the audit policy covers key security concerns (Manual)",
                    "severity": "HIGH"
                },
                {
                    "id": "5.1.1",
                    "name": "Ensure that the cluster-admin role is only used where required",
                    "severity": "HIGH",
                    "totalFail": 0
                },
                {
                    "id": "5.1.2",
                    "name": "Minimize access to secrets",
                    "severity": "HIGH",
                    "totalFail": 0
                },
                {
                    "id": "5.1.3",
                    "name": "Minimize wildcard use in Roles and ClusterRoles",
                    "severity": "HIGH",
                    "totalFail": 0
                },
                {
                    "id": "5.1.6",
                    "name": "Ensure that Service Account Tokens are only mounted where necessary",
                    "severity": "HIGH",
                    "totalFail": 1
                },
                {
                    "id": "5.1.8",
                    "name": "Limit use of the Bind, Impersonate and Escalate permissions in the Kubernetes cluster",
                    "severity": "HIGH",
                    "totalFail": 0
                },
                {
                    "id": "5.2.2",
                    "name": "Minimize the admission of privileged containers",
                    "severity": "HIGH",
                    "totalFail": 1
                },
                {
                    "id": "5.2.3",
                    "name": "Minimize the admission of containers wishing to share the host process ID namespace",
                    "severity": "HIGH",
                    "totalFail": 0
                },
                {
                    "id": "5.2.4",
                    "name": "Minimize the admission of containers wishing to share the host IPC namespace",
                    "severity": "HIGH",
                    "totalFail": 0
                },
                {
                    "id": "5.2.5",
                    "name": "Minimize the admission of containers wishing to share the host network namespace",
                    "severity": "HIGH",
                    "totalFail": 6
                },
                {
                    "id": "5.2.6",
                    "name": "Minimize the admission of containers with allowPrivilegeEscalation",
                    "severity": "HIGH",
                    "totalFail": 9
                },
                {
                    "id": "5.2.7",
                    "name": "Minimize the admission of root containers",
                    "severity": "MEDIUM",
                    "totalFail": 10
                },
                {
                    "id": "5.2.8",
                    "name": "Minimize the admission of containers with the NET_RAW capability",
                    "severity": "MEDIUM",
                    "totalFail": 2
                },
                {
                    "id": "5.2.9",
                    "name": "Minimize the admission of containers with added capabilities",
                    "severity": "LOW",
                    "totalFail": 0
                },
                {
                    "id": "5.2.10",
                    "name": "Minimize the admission of containers with capabilities assigned",
                    "severity": "LOW",
                    "totalFail": 9
                },
                {
                    "id": "5.2.11",
                    "name": "Minimize the admission of containers with capabilities assigned",
                    "severity": "MEDIUM",
                    "totalFail": 0
                },
                {
                    "id": "5.2.12",
                    "name": "Minimize the admission of HostPath volumes",
                    "severity": "MEDIUM",
                    "totalFail": 6
                },
                {
                    "id": "5.2.13",
                    "name": "Minimize the admission of containers which use HostPorts",
                    "severity": "MEDIUM",
                    "totalFail": 0
                },
                {
                    "id": "5.3.1",
                    "name": "Ensure that the CNI in use supports Network Policies (Manual)",
                    "severity": "MEDIUM"
                },
                {
                    "id": "5.3.2",
                    "name": "Ensure that all Namespaces have Network Policies defined",
                    "severity": "MEDIUM",
                    "totalFail": 0
                },
                {
                    "id": "5.4.1",
                    "name": "Prefer using secrets as files over secrets as environment variables (Manual)",
                    "severity": "MEDIUM"
                },
                {
                    "id": "5.4.2",
                    "name": "Consider external secret storage (Manual)",
                    "severity": "MEDIUM"
                },
                {
                    "id": "5.5.1",
                    "name": "Configure Image Provenance using ImagePolicyWebhook admission controller (Manual)",
                    "severity": "MEDIUM"
                },
                {
                    "id": "5.7.1",
                    "name": "Create administrative boundaries between resources using namespaces (Manual)",
                    "severity": "MEDIUM"
                },
                {
                    "id": "5.7.2",
                    "name": "Ensure that the seccomp profile is set to docker/default in your pod definitions",
                    "severity": "MEDIUM",
                    "totalFail": 0
                },
                {
                    "id": "5.7.3",
                    "name": "Apply Security Context to Your Pods and Containers",
                    "severity": "HIGH",
                    "totalFail": 30
                },
                {
                    "id": "5.7.4",
                    "name": "The default namespace should not be used",
                    "severity": "MEDIUM",
                    "totalFail": 3
                }
            ],
            "id": "cis",
            "title": "CIS Kubernetes Benchmarks v1.23"
        },
        "updateTimestamp": "2023-01-01T10:28:00Z"
    }
}
```

</details>
