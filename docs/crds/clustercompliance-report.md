# ClusterComplianceReport

The ClusterComplianceReport is a cluster-scoped resource, which represents the latest compliance control checks results.
The report spec defines a mapping between pre-defined compliance control check ids to security scanners check ids.
Currently, only `config-audit` security scanners are supported.

The NSA compliance report is composed of two parts:

- `spec:` represents the compliance control checks specification, check details, and the mapping to the security scanner
  (this part is defined by the user)
- `status:` represents the compliance control checks (as defined by spec mapping) results extracted from the security
  scanners reports (this part is output by trivy-operator)

The following shows a sample ClusterComplianceReport NSA specification associated with the `cluster` in summary format:

```yaml
apiVersion: aquasecurity.github.io/v1alpha1
kind: ClusterComplianceReport
metadata:
  annotations:
  creationTimestamp: "2022-12-04T13:56:11Z"
  generation: 3
  labels:
    app.kubernetes.io/instance: trivy-operator
    app.kubernetes.io/managed-by: kubectl
    app.kubernetes.io/name: trivy-operator
    app.kubernetes.io/version: 0.8.0
  name: nsa
  resourceVersion: "20819"
  uid: 345956c9-21b7-4b97-880c-06ef56ee71e4
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
  updateTimestamp: "2022-12-04T14:40:00Z"

```



The following shows a sample ClusterComplianceReport NSA specification associated with the `cluster` in detail(all) format:

```yaml
{
  "apiVersion": "aquasecurity.github.io/v1alpha1",
  "kind": "ClusterComplianceReport",
  "metadata": {
    "creationTimestamp": "2022-12-04T18:25:27Z",
    "generation": 2,
    "labels": {
      "app.kubernetes.io/instance": "trivy-operator",
      "app.kubernetes.io/managed-by": "kubectl",
      "app.kubernetes.io/name": "trivy-operator",
      "app.kubernetes.io/version": "0.8.0"
    },
    "name": "nsa",
    "resourceVersion": "44129",
    "uid": "d9991808-fb2f-4756-842f-8e9205e85b71"
  },
  "spec": {
    "compliance": {
      "controls": [
        {
          "checks": [
            {
              "id": "AVD-KSV-0012"
            }
          ],
          "description": "Check that container is not running as root",
          "id": "1.0",
          "name": "Non-root containers",
          "severity": "MEDIUM"
        },
        {
          "checks": [
            {
              "id": "AVD-KSV-0014"
            }
          ],
          "description": "Check that container root file system is immutable",
          "id": "1.1",
          "name": "Immutable container file systems",
          "severity": "LOW"
        },
        {
          "checks": [
            {
              "id": "AVD-KSV-0017"
            }
          ],
          "description": "Controls whether Pods can run privileged containers",
          "id": "1.2",
          "name": "Preventing privileged containers",
          "severity": "HIGH"
        },
        {
          "checks": [
            {
              "id": "AVD-KSV-0008"
            }
          ],
          "description": "Controls whether containers can share process namespaces",
          "id": "1.3",
          "name": "Share containers process namespaces",
          "severity": "HIGH"
        },
        {
          "checks": [
            {
              "id": "AVD-KSV-0009"
            }
          ],
          "description": "Controls whether share host process namespaces",
          "id": "1.4",
          "name": "Share host process namespaces",
          "severity": "HIGH"
        },
        {
          "checks": [
            {
              "id": "AVD-KSV-0010"
            }
          ],
          "description": "Controls whether containers can use the host network",
          "id": "1.5",
          "name": "Use the host network",
          "severity": "HIGH"
        },
        {
          "checks": [
            {
              "id": "AVD-KSV-0029"
            }
          ],
          "description": "Controls whether container applications can run with root privileges or with root group membership",
          "id": "1.6",
          "name": "Run with root privileges or with root group membership",
          "severity": "LOW"
        },
        {
          "checks": [
            {
              "id": "AVD-KSV-0001"
            }
          ],
          "description": "Control check restrictions escalation to root privileges",
          "id": "1.7",
          "name": "Restricts escalation to root privileges",
          "severity": "MEDIUM"
        },
        {
          "checks": [
            {
              "id": "AVD-KSV-0002"
            }
          ],
          "description": "Control checks if pod sets the SELinux context of the container",
          "id": "1.8",
          "name": "Sets the SELinux context of the container",
          "severity": "MEDIUM"
        },
        {
          "checks": [
            {
              "id": "AVD-KSV-0030"
            }
          ],
          "description": "Control checks the restriction of containers access to resources with AppArmor",
          "id": "1.9",
          "name": "Restrict a container's access to resources with AppArmor",
          "severity": "MEDIUM"
        },
        {
          "checks": [
            {
              "id": "AVD-KSV-0030"
            }
          ],
          "description": "Control checks the sets the seccomp profile used to sandbox containers",
          "id": "1.10",
          "name": "Sets the seccomp profile used to sandbox containers.",
          "severity": "LOW"
        },
        {
          "checks": [
            {
              "id": "AVD-KSV-0036"
            }
          ],
          "description": "Control check whether disable secret token been mount ,automountServiceAccountToken: false",
          "id": "1.11",
          "name": "Protecting Pod service account tokens",
          "severity": "MEDIUM"
        },
        {
          "checks": [
            {
              "id": "AVD-KSV-0037"
            }
          ],
          "defaultStatus": "FAIL",
          "description": "Control check whether Namespace kube-system is not be used by users",
          "id": "1.12",
          "name": "Namespace kube-system should not be used by users",
          "severity": "MEDIUM"
        },
        {
          "checks": [
            {
              "id": "AVD-KSV-0038"
            }
          ],
          "defaultStatus": "FAIL",
          "description": "Control check validate the pod and/or namespace Selectors usage",
          "id": "2.0",
          "name": "Pod and/or namespace Selectors usage",
          "severity": "MEDIUM"
        },
        {
          "defaultStatus": "FAIL",
          "description": "Control check whether check cni plugin installed",
          "id": "3.0",
          "name": "Use CNI plugin that supports NetworkPolicy API (Manual)",
          "severity": "CRITICAL"
        },
        {
          "checks": [
            {
              "id": "AVD-KSV-0040"
            }
          ],
          "defaultStatus": "FAIL",
          "description": "Control check the use of ResourceQuota policy to limit aggregate resource usage within namespace",
          "id": "4.0",
          "name": "Use ResourceQuota policies to limit resources",
          "severity": "MEDIUM"
        },
        {
          "checks": [
            {
              "id": "AVD-KSV-0039"
            }
          ],
          "defaultStatus": "FAIL",
          "description": "Control check the use of LimitRange policy limit resource usage for namespaces or nodes",
          "id": "4.1",
          "name": "Use LimitRange policies to limit resources",
          "severity": "MEDIUM"
        },
        {
          "defaultStatus": "FAIL",
          "description": "Control check whether control plan disable insecure port",
          "id": "5.0",
          "name": "Control plan disable insecure port (Manual)",
          "severity": "CRITICAL"
        },
        {
          "checks": [
            {
              "id": "AVD-KCV-0030"
            }
          ],
          "description": "Control check whether etcd communication is encrypted",
          "id": "5.1",
          "name": "Encrypt etcd communication",
          "severity": "CRITICAL"
        },
        {
          "defaultStatus": "FAIL",
          "description": "Control check whether kube config file permissions",
          "id": "6.0",
          "name": "Ensure kube config file permission (Manual)",
          "severity": "CRITICAL"
        },
        {
          "checks": [
            {
              "id": "AVD-KCV-0029"
            }
          ],
          "description": "Control checks whether encryption resource has been set",
          "id": "6.1",
          "name": "Check that encryption resource has been set",
          "severity": "CRITICAL"
        },
        {
          "checks": [
            {
              "id": "AVD-KCV-0004"
            }
          ],
          "description": "Control checks whether encryption provider has been set",
          "id": "6.2",
          "name": "Check encryption provider",
          "severity": "CRITICAL"
        },
        {
          "checks": [
            {
              "id": "AVD-KCV-0001"
            }
          ],
          "description": "Control checks whether anonymous-auth is unset",
          "id": "7.0",
          "name": "Make sure anonymous-auth is unset",
          "severity": "CRITICAL"
        },
        {
          "checks": [
            {
              "id": "AVD-KCV-0008"
            }
          ],
          "description": "Control check whether RBAC permission is in use",
          "id": "7.1",
          "name": "Make sure -authorization-mode=RBAC",
          "severity": "CRITICAL"
        },
        {
          "defaultStatus": "FAIL",
          "description": "Control check whether audit policy is configure",
          "id": "8.0",
          "name": "Audit policy is configure (Manual)",
          "severity": "HIGH"
        },
        {
          "checks": [
            {
              "id": "AVD-KCV-0019"
            }
          ],
          "description": "Control check whether audit log path is configure",
          "id": "8.1",
          "name": "Audit log path is configure",
          "severity": "MEDIUM"
        },
        {
          "checks": [
            {
              "id": "AVD-KCV-0020"
            }
          ],
          "description": "Control check whether audit log aging is configure",
          "id": "8.2",
          "name": "Audit log aging",
          "severity": "MEDIUM"
        }
      ],
      "description": "National Security Agency - Kubernetes Hardening Guidance",
      "id": "0001",
      "relatedResources": [
        "https://www.nsa.gov/Press-Room/News-Highlights/Article/Article/2716980/nsa-cisa-release-kubernetes-hardening-guidance/"
      ],
      "title": "nsa",
      "version": "1.0"
    },
    "cron": "* * * * *",
    "reportType": "all"
  },
  "status": {
    "detailReport": {
      "description": "National Security Agency - Kubernetes Hardening Guidance",
      "id": "0001",
      "relatedVersion": [
        "https://www.nsa.gov/Press-Room/News-Highlights/Article/Article/2716980/nsa-cisa-release-kubernetes-hardening-guidance/"
      ],
      "results": [
        {
          "checks": [
            {
              "category": "Kubernetes Security Check",
              "checkID": "AVD-KSV-0012",
              "description": "'runAsNonRoot' forces the running image to run as a non-root user to ensure least privileges.",
              "messages": [
                "'runAsNonRoot' forces the running image to run as a non-root user to ensure least privileges."
              ],
              "severity": "MEDIUM",
              "success": false,
              "target": "kube-system/pod-kube-apiserver-kind-control-plane",
              "title": "Runs as root user"
            },
            {
              "category": "Kubernetes Security Check",
              "checkID": "AVD-KSV-0012",
              "description": "'runAsNonRoot' forces the running image to run as a non-root user to ensure least privileges.",
              "messages": [
                "'runAsNonRoot' forces the running image to run as a non-root user to ensure least privileges."
              ],
              "severity": "MEDIUM",
              "success": false,
              "target": "kube-system/replicaset-coredns-558bd4d5db",
              "title": "Runs as root user"
            },
            {
              "category": "Kubernetes Security Check",
              "checkID": "AVD-KSV-0012",
              "description": "'runAsNonRoot' forces the running image to run as a non-root user to ensure least privileges.",
              "messages": [
                "'runAsNonRoot' forces the running image to run as a non-root user to ensure least privileges."
              ],
              "severity": "MEDIUM",
              "success": false,
              "target": "kube-system/pod-kube-scheduler-kind-control-plane",
              "title": "Runs as root user"
            },
            {
              "category": "Kubernetes Security Check",
              "checkID": "AVD-KSV-0012",
              "description": "'runAsNonRoot' forces the running image to run as a non-root user to ensure least privileges.",
              "messages": [
                "'runAsNonRoot' forces the running image to run as a non-root user to ensure least privileges."
              ],
              "severity": "MEDIUM",
              "success": false,
              "target": "kube-system/daemonset-kindnet",
              "title": "Runs as root user"
            },
            {
              "category": "Kubernetes Security Check",
              "checkID": "AVD-KSV-0012",
              "description": "'runAsNonRoot' forces the running image to run as a non-root user to ensure least privileges.",
              "messages": [
                "'runAsNonRoot' forces the running image to run as a non-root user to ensure least privileges."
              ],
              "severity": "MEDIUM",
              "success": false,
              "target": "kube-system/daemonset-kube-proxy",
              "title": "Runs as root user"
            },
            {
              "category": "Kubernetes Security Check",
              "checkID": "AVD-KSV-0012",
              "description": "'runAsNonRoot' forces the running image to run as a non-root user to ensure least privileges.",
              "messages": [
                "'runAsNonRoot' forces the running image to run as a non-root user to ensure least privileges."
              ],
              "severity": "MEDIUM",
              "success": false,
              "target": "local-path-storage/replicaset-local-path-provisioner-547f784dff",
              "title": "Runs as root user"
            },
            {
              "category": "Kubernetes Security Check",
              "checkID": "AVD-KSV-0012",
              "description": "'runAsNonRoot' forces the running image to run as a non-root user to ensure least privileges.",
              "messages": [
                "'runAsNonRoot' forces the running image to run as a non-root user to ensure least privileges."
              ],
              "severity": "MEDIUM",
              "success": false,
              "target": "kube-system/pod-kube-controller-manager-kind-control-plane",
              "title": "Runs as root user"
            },
            {
              "category": "Kubernetes Security Check",
              "checkID": "AVD-KSV-0012",
              "description": "'runAsNonRoot' forces the running image to run as a non-root user to ensure least privileges.",
              "messages": [
                "'runAsNonRoot' forces the running image to run as a non-root user to ensure least privileges."
              ],
              "severity": "MEDIUM",
              "success": false,
              "target": "kube-system/pod-etcd-kind-control-plane",
              "title": "Runs as root user"
            }
          ],
          "description": "Check that container is not running as root",
          "id": "1.0",
          "name": "Non-root containers",
          "severity": "MEDIUM"
        },
        {
          "checks": [
            {
              "category": "Kubernetes Security Check",
              "checkID": "AVD-KSV-0014",
              "description": "An immutable root file system prevents applications from writing to their local disk. This can limit intrusions, as attackers will not be able to tamper with the file system or write foreign executables to disk.",
              "messages": [
                "An immutable root file system prevents applications from writing to their local disk. This can limit intrusions, as attackers will not be able to tamper with the file system or write foreign executables to disk."
              ],
              "severity": "LOW",
              "success": false,
              "target": "kube-system/pod-kube-apiserver-kind-control-plane",
              "title": "Root file system is not read-only"
            },
            {
              "category": "Kubernetes Security Check",
              "checkID": "AVD-KSV-0014",
              "description": "An immutable root file system prevents applications from writing to their local disk. This can limit intrusions, as attackers will not be able to tamper with the file system or write foreign executables to disk.",
              "messages": [
                "An immutable root file system prevents applications from writing to their local disk. This can limit intrusions, as attackers will not be able to tamper with the file system or write foreign executables to disk."
              ],
              "severity": "LOW",
              "success": false,
              "target": "kube-system/pod-kube-scheduler-kind-control-plane",
              "title": "Root file system is not read-only"
            },
            {
              "category": "Kubernetes Security Check",
              "checkID": "AVD-KSV-0014",
              "description": "An immutable root file system prevents applications from writing to their local disk. This can limit intrusions, as attackers will not be able to tamper with the file system or write foreign executables to disk.",
              "messages": [
                "An immutable root file system prevents applications from writing to their local disk. This can limit intrusions, as attackers will not be able to tamper with the file system or write foreign executables to disk."
              ],
              "severity": "LOW",
              "success": false,
              "target": "kube-system/daemonset-kindnet",
              "title": "Root file system is not read-only"
            },
            {
              "category": "Kubernetes Security Check",
              "checkID": "AVD-KSV-0014",
              "description": "An immutable root file system prevents applications from writing to their local disk. This can limit intrusions, as attackers will not be able to tamper with the file system or write foreign executables to disk.",
              "messages": [
                "An immutable root file system prevents applications from writing to their local disk. This can limit intrusions, as attackers will not be able to tamper with the file system or write foreign executables to disk."
              ],
              "severity": "LOW",
              "success": false,
              "target": "kube-system/daemonset-kube-proxy",
              "title": "Root file system is not read-only"
            },
            {
              "category": "Kubernetes Security Check",
              "checkID": "AVD-KSV-0014",
              "description": "An immutable root file system prevents applications from writing to their local disk. This can limit intrusions, as attackers will not be able to tamper with the file system or write foreign executables to disk.",
              "messages": [
                "An immutable root file system prevents applications from writing to their local disk. This can limit intrusions, as attackers will not be able to tamper with the file system or write foreign executables to disk."
              ],
              "severity": "LOW",
              "success": false,
              "target": "local-path-storage/replicaset-local-path-provisioner-547f784dff",
              "title": "Root file system is not read-only"
            },
            {
              "category": "Kubernetes Security Check",
              "checkID": "AVD-KSV-0014",
              "description": "An immutable root file system prevents applications from writing to their local disk. This can limit intrusions, as attackers will not be able to tamper with the file system or write foreign executables to disk.",
              "messages": [
                "An immutable root file system prevents applications from writing to their local disk. This can limit intrusions, as attackers will not be able to tamper with the file system or write foreign executables to disk."
              ],
              "severity": "LOW",
              "success": false,
              "target": "kube-system/pod-kube-controller-manager-kind-control-plane",
              "title": "Root file system is not read-only"
            },
            {
              "category": "Kubernetes Security Check",
              "checkID": "AVD-KSV-0014",
              "description": "An immutable root file system prevents applications from writing to their local disk. This can limit intrusions, as attackers will not be able to tamper with the file system or write foreign executables to disk.",
              "messages": [
                "An immutable root file system prevents applications from writing to their local disk. This can limit intrusions, as attackers will not be able to tamper with the file system or write foreign executables to disk."
              ],
              "severity": "LOW",
              "success": false,
              "target": "kube-system/pod-etcd-kind-control-plane",
              "title": "Root file system is not read-only"
            }
          ],
          "description": "Check that container root file system is immutable",
          "id": "1.1",
          "name": "Immutable container file systems",
          "severity": "LOW"
        },
        {
          "checks": [
            {
              "category": "Kubernetes Security Check",
              "checkID": "AVD-KSV-0017",
              "description": "Privileged containers share namespaces with the host system and do not offer any security. They should be used exclusively for system containers that require high privileges.",
              "messages": [
                "Privileged containers share namespaces with the host system and do not offer any security. They should be used exclusively for system containers that require high privileges."
              ],
              "severity": "HIGH",
              "success": false,
              "target": "kube-system/daemonset-kube-proxy",
              "title": "Privileged container"
            }
          ],
          "description": "Controls whether Pods can run privileged containers",
          "id": "1.2",
          "name": "Preventing privileged containers",
          "severity": "HIGH"
        },
        {
          "checks": [
            {
              "checkID": "",
              "severity": "",
              "success": true
            }
          ],
          "description": "Controls whether containers can share process namespaces",
          "id": "1.3",
          "name": "Share containers process namespaces",
          "severity": "HIGH"
        },
        {
          "checks": [
            {
              "category": "Kubernetes Security Check",
              "checkID": "AVD-KSV-0009",
              "description": "Sharing the host’s network namespace permits processes in the pod to communicate with processes bound to the host’s loopback adapter.",
              "messages": [
                "Sharing the host’s network namespace permits processes in the pod to communicate with processes bound to the host’s loopback adapter."
              ],
              "severity": "HIGH",
              "success": false,
              "target": "kube-system/pod-kube-apiserver-kind-control-plane",
              "title": "Access to host network"
            },
            {
              "category": "Kubernetes Security Check",
              "checkID": "AVD-KSV-0009",
              "description": "Sharing the host’s network namespace permits processes in the pod to communicate with processes bound to the host’s loopback adapter.",
              "messages": [
                "Sharing the host’s network namespace permits processes in the pod to communicate with processes bound to the host’s loopback adapter."
              ],
              "severity": "HIGH",
              "success": false,
              "target": "kube-system/pod-kube-scheduler-kind-control-plane",
              "title": "Access to host network"
            },
            {
              "category": "Kubernetes Security Check",
              "checkID": "AVD-KSV-0009",
              "description": "Sharing the host’s network namespace permits processes in the pod to communicate with processes bound to the host’s loopback adapter.",
              "messages": [
                "Sharing the host’s network namespace permits processes in the pod to communicate with processes bound to the host’s loopback adapter."
              ],
              "severity": "HIGH",
              "success": false,
              "target": "kube-system/daemonset-kindnet",
              "title": "Access to host network"
            },
            {
              "category": "Kubernetes Security Check",
              "checkID": "AVD-KSV-0009",
              "description": "Sharing the host’s network namespace permits processes in the pod to communicate with processes bound to the host’s loopback adapter.",
              "messages": [
                "Sharing the host’s network namespace permits processes in the pod to communicate with processes bound to the host’s loopback adapter."
              ],
              "severity": "HIGH",
              "success": false,
              "target": "kube-system/daemonset-kube-proxy",
              "title": "Access to host network"
            },
            {
              "category": "Kubernetes Security Check",
              "checkID": "AVD-KSV-0009",
              "description": "Sharing the host’s network namespace permits processes in the pod to communicate with processes bound to the host’s loopback adapter.",
              "messages": [
                "Sharing the host’s network namespace permits processes in the pod to communicate with processes bound to the host’s loopback adapter."
              ],
              "severity": "HIGH",
              "success": false,
              "target": "kube-system/pod-kube-controller-manager-kind-control-plane",
              "title": "Access to host network"
            },
            {
              "category": "Kubernetes Security Check",
              "checkID": "AVD-KSV-0009",
              "description": "Sharing the host’s network namespace permits processes in the pod to communicate with processes bound to the host’s loopback adapter.",
              "messages": [
                "Sharing the host’s network namespace permits processes in the pod to communicate with processes bound to the host’s loopback adapter."
              ],
              "severity": "HIGH",
              "success": false,
              "target": "kube-system/pod-etcd-kind-control-plane",
              "title": "Access to host network"
            }
          ],
          "description": "Controls whether share host process namespaces",
          "id": "1.4",
          "name": "Share host process namespaces",
          "severity": "HIGH"
        },
        {
          "checks": [
            {
              "checkID": "",
              "severity": "",
              "success": true
            }
          ],
          "description": "Controls whether containers can use the host network",
          "id": "1.5",
          "name": "Use the host network",
          "severity": "HIGH"
        },
        {
          "checks": [
            {
              "checkID": "",
              "severity": "",
              "success": true
            }
          ],
          "description": "Controls whether container applications can run with root privileges or with root group membership",
          "id": "1.6",
          "name": "Run with root privileges or with root group membership",
          "severity": "LOW"
        },
        {
          "checks": [
            {
              "category": "Kubernetes Security Check",
              "checkID": "AVD-KSV-0001",
              "description": "A program inside the container can elevate its own privileges and run as root, which might give the program control over the container and node.",
              "messages": [
                "A program inside the container can elevate its own privileges and run as root, which might give the program control over the container and node."
              ],
              "severity": "MEDIUM",
              "success": false,
              "target": "kube-system/pod-kube-apiserver-kind-control-plane",
              "title": "Process can elevate its own privileges"
            },
            {
              "category": "Kubernetes Security Check",
              "checkID": "AVD-KSV-0001",
              "description": "A program inside the container can elevate its own privileges and run as root, which might give the program control over the container and node.",
              "messages": [
                "A program inside the container can elevate its own privileges and run as root, which might give the program control over the container and node."
              ],
              "severity": "MEDIUM",
              "success": false,
              "target": "kube-system/pod-kube-scheduler-kind-control-plane",
              "title": "Process can elevate its own privileges"
            },
            {
              "category": "Kubernetes Security Check",
              "checkID": "AVD-KSV-0001",
              "description": "A program inside the container can elevate its own privileges and run as root, which might give the program control over the container and node.",
              "messages": [
                "A program inside the container can elevate its own privileges and run as root, which might give the program control over the container and node."
              ],
              "severity": "MEDIUM",
              "success": false,
              "target": "kube-system/daemonset-kindnet",
              "title": "Process can elevate its own privileges"
            },
            {
              "category": "Kubernetes Security Check",
              "checkID": "AVD-KSV-0001",
              "description": "A program inside the container can elevate its own privileges and run as root, which might give the program control over the container and node.",
              "messages": [
                "A program inside the container can elevate its own privileges and run as root, which might give the program control over the container and node."
              ],
              "severity": "MEDIUM",
              "success": false,
              "target": "kube-system/daemonset-kube-proxy",
              "title": "Process can elevate its own privileges"
            },
            {
              "category": "Kubernetes Security Check",
              "checkID": "AVD-KSV-0001",
              "description": "A program inside the container can elevate its own privileges and run as root, which might give the program control over the container and node.",
              "messages": [
                "A program inside the container can elevate its own privileges and run as root, which might give the program control over the container and node."
              ],
              "severity": "MEDIUM",
              "success": false,
              "target": "local-path-storage/replicaset-local-path-provisioner-547f784dff",
              "title": "Process can elevate its own privileges"
            },
            {
              "category": "Kubernetes Security Check",
              "checkID": "AVD-KSV-0001",
              "description": "A program inside the container can elevate its own privileges and run as root, which might give the program control over the container and node.",
              "messages": [
                "A program inside the container can elevate its own privileges and run as root, which might give the program control over the container and node."
              ],
              "severity": "MEDIUM",
              "success": false,
              "target": "kube-system/pod-kube-controller-manager-kind-control-plane",
              "title": "Process can elevate its own privileges"
            },
            {
              "category": "Kubernetes Security Check",
              "checkID": "AVD-KSV-0001",
              "description": "A program inside the container can elevate its own privileges and run as root, which might give the program control over the container and node.",
              "messages": [
                "A program inside the container can elevate its own privileges and run as root, which might give the program control over the container and node."
              ],
              "severity": "MEDIUM",
              "success": false,
              "target": "kube-system/pod-etcd-kind-control-plane",
              "title": "Process can elevate its own privileges"
            }
          ],
          "description": "Control check restrictions escalation to root privileges",
          "id": "1.7",
          "name": "Restricts escalation to root privileges",
          "severity": "MEDIUM"
        },
        {
          "checks": [
            {
              "checkID": "",
              "severity": "",
              "success": true
            }
          ],
          "description": "Control checks if pod sets the SELinux context of the container",
          "id": "1.8",
          "name": "Sets the SELinux context of the container",
          "severity": "MEDIUM"
        },
        {
          "checks": [
            {
              "category": "Kubernetes Security Check",
              "checkID": "AVD-KSV-0030",
              "description": "The RuntimeDefault/Localhost seccomp profile must be required, or allow specific additional profiles.",
              "messages": [
                "The RuntimeDefault/Localhost seccomp profile must be required, or allow specific additional profiles."
              ],
              "severity": "LOW",
              "success": false,
              "target": "kube-system/pod-kube-apiserver-kind-control-plane",
              "title": "Default Seccomp profile not set"
            },
            {
              "category": "Kubernetes Security Check",
              "checkID": "AVD-KSV-0030",
              "description": "The RuntimeDefault/Localhost seccomp profile must be required, or allow specific additional profiles.",
              "messages": [
                "The RuntimeDefault/Localhost seccomp profile must be required, or allow specific additional profiles."
              ],
              "severity": "LOW",
              "success": false,
              "target": "kube-system/replicaset-coredns-558bd4d5db",
              "title": "Default Seccomp profile not set"
            },
            {
              "category": "Kubernetes Security Check",
              "checkID": "AVD-KSV-0030",
              "description": "The RuntimeDefault/Localhost seccomp profile must be required, or allow specific additional profiles.",
              "messages": [
                "The RuntimeDefault/Localhost seccomp profile must be required, or allow specific additional profiles."
              ],
              "severity": "LOW",
              "success": false,
              "target": "kube-system/pod-kube-scheduler-kind-control-plane",
              "title": "Default Seccomp profile not set"
            },
            {
              "category": "Kubernetes Security Check",
              "checkID": "AVD-KSV-0030",
              "description": "The RuntimeDefault/Localhost seccomp profile must be required, or allow specific additional profiles.",
              "messages": [
                "The RuntimeDefault/Localhost seccomp profile must be required, or allow specific additional profiles."
              ],
              "severity": "LOW",
              "success": false,
              "target": "kube-system/daemonset-kindnet",
              "title": "Default Seccomp profile not set"
            },
            {
              "category": "Kubernetes Security Check",
              "checkID": "AVD-KSV-0030",
              "description": "The RuntimeDefault/Localhost seccomp profile must be required, or allow specific additional profiles.",
              "messages": [
                "The RuntimeDefault/Localhost seccomp profile must be required, or allow specific additional profiles."
              ],
              "severity": "LOW",
              "success": false,
              "target": "kube-system/daemonset-kube-proxy",
              "title": "Default Seccomp profile not set"
            },
            {
              "category": "Kubernetes Security Check",
              "checkID": "AVD-KSV-0030",
              "description": "The RuntimeDefault/Localhost seccomp profile must be required, or allow specific additional profiles.",
              "messages": [
                "The RuntimeDefault/Localhost seccomp profile must be required, or allow specific additional profiles."
              ],
              "severity": "LOW",
              "success": false,
              "target": "local-path-storage/replicaset-local-path-provisioner-547f784dff",
              "title": "Default Seccomp profile not set"
            },
            {
              "category": "Kubernetes Security Check",
              "checkID": "AVD-KSV-0030",
              "description": "The RuntimeDefault/Localhost seccomp profile must be required, or allow specific additional profiles.",
              "messages": [
                "The RuntimeDefault/Localhost seccomp profile must be required, or allow specific additional profiles."
              ],
              "severity": "LOW",
              "success": false,
              "target": "kube-system/pod-kube-controller-manager-kind-control-plane",
              "title": "Default Seccomp profile not set"
            },
            {
              "category": "Kubernetes Security Check",
              "checkID": "AVD-KSV-0030",
              "description": "The RuntimeDefault/Localhost seccomp profile must be required, or allow specific additional profiles.",
              "messages": [
                "The RuntimeDefault/Localhost seccomp profile must be required, or allow specific additional profiles."
              ],
              "severity": "LOW",
              "success": false,
              "target": "kube-system/pod-etcd-kind-control-plane",
              "title": "Default Seccomp profile not set"
            }
          ],
          "description": "Control checks the restriction of containers access to resources with AppArmor",
          "id": "1.9",
          "name": "Restrict a container's access to resources with AppArmor",
          "severity": "MEDIUM"
        },
        {
          "checks": [
            {
              "category": "Kubernetes Security Check",
              "checkID": "AVD-KSV-0030",
              "description": "The RuntimeDefault/Localhost seccomp profile must be required, or allow specific additional profiles.",
              "messages": [
                "The RuntimeDefault/Localhost seccomp profile must be required, or allow specific additional profiles."
              ],
              "severity": "LOW",
              "success": false,
              "target": "kube-system/pod-kube-apiserver-kind-control-plane",
              "title": "Default Seccomp profile not set"
            },
            {
              "category": "Kubernetes Security Check",
              "checkID": "AVD-KSV-0030",
              "description": "The RuntimeDefault/Localhost seccomp profile must be required, or allow specific additional profiles.",
              "messages": [
                "The RuntimeDefault/Localhost seccomp profile must be required, or allow specific additional profiles."
              ],
              "severity": "LOW",
              "success": false,
              "target": "kube-system/replicaset-coredns-558bd4d5db",
              "title": "Default Seccomp profile not set"
            },
            {
              "category": "Kubernetes Security Check",
              "checkID": "AVD-KSV-0030",
              "description": "The RuntimeDefault/Localhost seccomp profile must be required, or allow specific additional profiles.",
              "messages": [
                "The RuntimeDefault/Localhost seccomp profile must be required, or allow specific additional profiles."
              ],
              "severity": "LOW",
              "success": false,
              "target": "kube-system/pod-kube-scheduler-kind-control-plane",
              "title": "Default Seccomp profile not set"
            },
            {
              "category": "Kubernetes Security Check",
              "checkID": "AVD-KSV-0030",
              "description": "The RuntimeDefault/Localhost seccomp profile must be required, or allow specific additional profiles.",
              "messages": [
                "The RuntimeDefault/Localhost seccomp profile must be required, or allow specific additional profiles."
              ],
              "severity": "LOW",
              "success": false,
              "target": "kube-system/daemonset-kindnet",
              "title": "Default Seccomp profile not set"
            },
            {
              "category": "Kubernetes Security Check",
              "checkID": "AVD-KSV-0030",
              "description": "The RuntimeDefault/Localhost seccomp profile must be required, or allow specific additional profiles.",
              "messages": [
                "The RuntimeDefault/Localhost seccomp profile must be required, or allow specific additional profiles."
              ],
              "severity": "LOW",
              "success": false,
              "target": "kube-system/daemonset-kube-proxy",
              "title": "Default Seccomp profile not set"
            },
            {
              "category": "Kubernetes Security Check",
              "checkID": "AVD-KSV-0030",
              "description": "The RuntimeDefault/Localhost seccomp profile must be required, or allow specific additional profiles.",
              "messages": [
                "The RuntimeDefault/Localhost seccomp profile must be required, or allow specific additional profiles."
              ],
              "severity": "LOW",
              "success": false,
              "target": "local-path-storage/replicaset-local-path-provisioner-547f784dff",
              "title": "Default Seccomp profile not set"
            },
            {
              "category": "Kubernetes Security Check",
              "checkID": "AVD-KSV-0030",
              "description": "The RuntimeDefault/Localhost seccomp profile must be required, or allow specific additional profiles.",
              "messages": [
                "The RuntimeDefault/Localhost seccomp profile must be required, or allow specific additional profiles."
              ],
              "severity": "LOW",
              "success": false,
              "target": "kube-system/pod-kube-controller-manager-kind-control-plane",
              "title": "Default Seccomp profile not set"
            },
            {
              "category": "Kubernetes Security Check",
              "checkID": "AVD-KSV-0030",
              "description": "The RuntimeDefault/Localhost seccomp profile must be required, or allow specific additional profiles.",
              "messages": [
                "The RuntimeDefault/Localhost seccomp profile must be required, or allow specific additional profiles."
              ],
              "severity": "LOW",
              "success": false,
              "target": "kube-system/pod-etcd-kind-control-plane",
              "title": "Default Seccomp profile not set"
            }
          ],
          "description": "Control checks the sets the seccomp profile used to sandbox containers",
          "id": "1.10",
          "name": "Sets the seccomp profile used to sandbox containers.",
          "severity": "LOW"
        },
        {
          "checks": [
            {
              "checkID": "",
              "severity": "",
              "success": true
            }
          ],
          "description": "Control check whether disable secret token been mount ,automountServiceAccountToken: false",
          "id": "1.11",
          "name": "Protecting Pod service account tokens",
          "severity": "MEDIUM"
        },
        {
          "checks": [
            {
              "category": "Kubernetes Security Check",
              "checkID": "AVD-KSV-0037",
              "description": "ensure that User pods are not placed in kube-system namespace",
              "messages": [
                "ensure that User pods are not placed in kube-system namespace"
              ],
              "severity": "MEDIUM",
              "success": false,
              "target": "kube-system/service-kube-dns",
              "title": "User Pods should not be placed in kube-system namespace"
            },
            {
              "category": "Kubernetes Security Check",
              "checkID": "AVD-KSV-0037",
              "description": "ensure that User pods are not placed in kube-system namespace",
              "messages": [
                "ensure that User pods are not placed in kube-system namespace"
              ],
              "severity": "MEDIUM",
              "success": false,
              "target": "kube-system/replicaset-coredns-558bd4d5db",
              "title": "User Pods should not be placed in kube-system namespace"
            },
            {
              "category": "Kubernetes Security Check",
              "checkID": "AVD-KSV-0037",
              "description": "ensure that User pods are not placed in kube-system namespace",
              "messages": [
                "ensure that User pods are not placed in kube-system namespace"
              ],
              "severity": "MEDIUM",
              "success": false,
              "target": "kube-system/daemonset-kindnet",
              "title": "User Pods should not be placed in kube-system namespace"
            },
            {
              "category": "Kubernetes Security Check",
              "checkID": "AVD-KSV-0037",
              "description": "ensure that User pods are not placed in kube-system namespace",
              "messages": [
                "ensure that User pods are not placed in kube-system namespace"
              ],
              "severity": "MEDIUM",
              "success": false,
              "target": "kube-system/daemonset-kube-proxy",
              "title": "User Pods should not be placed in kube-system namespace"
            }
          ],
          "description": "Control check whether Namespace kube-system is not be used by users",
          "id": "1.12",
          "name": "Namespace kube-system should not be used by users",
          "severity": "MEDIUM",
          "status": "FAIL"
        },
        {
          "checks": [
            {
              "checkID": "",
              "severity": "",
              "success": true
            }
          ],
          "description": "Control check validate the pod and/or namespace Selectors usage",
          "id": "2.0",
          "name": "Pod and/or namespace Selectors usage",
          "severity": "MEDIUM",
          "status": "FAIL"
        },
        {
          "checks": [
            {
              "checkID": "",
              "severity": "",
              "success": true
            }
          ],
          "description": "Control check whether check cni plugin installed",
          "id": "3.0",
          "name": "Use CNI plugin that supports NetworkPolicy API (Manual)",
          "severity": "CRITICAL",
          "status": "FAIL"
        },
        {
          "checks": [
            {
              "checkID": "",
              "severity": "",
              "success": true
            }
          ],
          "description": "Control check the use of ResourceQuota policy to limit aggregate resource usage within namespace",
          "id": "4.0",
          "name": "Use ResourceQuota policies to limit resources",
          "severity": "MEDIUM",
          "status": "FAIL"
        },
        {
          "checks": [
            {
              "checkID": "",
              "severity": "",
              "success": true
            }
          ],
          "description": "Control check the use of LimitRange policy limit resource usage for namespaces or nodes",
          "id": "4.1",
          "name": "Use LimitRange policies to limit resources",
          "severity": "MEDIUM",
          "status": "FAIL"
        },
        {
          "checks": [
            {
              "checkID": "",
              "severity": "",
              "success": true
            }
          ],
          "description": "Control check whether control plan disable insecure port",
          "id": "5.0",
          "name": "Control plan disable insecure port (Manual)",
          "severity": "CRITICAL",
          "status": "FAIL"
        },
        {
          "checks": [
            {
              "checkID": "",
              "severity": "",
              "success": true
            }
          ],
          "description": "Control check whether etcd communication is encrypted",
          "id": "5.1",
          "name": "Encrypt etcd communication",
          "severity": "CRITICAL"
        },
        {
          "checks": [
            {
              "checkID": "",
              "severity": "",
              "success": true
            }
          ],
          "description": "Control check whether kube config file permissions",
          "id": "6.0",
          "name": "Ensure kube config file permission (Manual)",
          "severity": "CRITICAL",
          "status": "FAIL"
        },
        {
          "checks": [
            {
              "category": "Kubernetes Security Check",
              "checkID": "AVD-KCV-0029",
              "description": "etcd should be configured to make use of TLS encryption for client connections.",
              "messages": [
                "etcd should be configured to make use of TLS encryption for client connections."
              ],
              "severity": "LOW",
              "success": false,
              "target": "kube-system/pod-kube-apiserver-kind-control-plane",
              "title": "Ensure that the --etcd-cafile argument is set as appropriate"
            }
          ],
          "description": "Control checks whether encryption resource has been set",
          "id": "6.1",
          "name": "Check that encryption resource has been set",
          "severity": "CRITICAL"
        },
        {
          "checks": [
            {
              "checkID": "",
              "severity": "",
              "success": true
            }
          ],
          "description": "Control checks whether encryption provider has been set",
          "id": "6.2",
          "name": "Check encryption provider",
          "severity": "CRITICAL"
        },
        {
          "checks": [
            {
              "category": "Kubernetes Security Check",
              "checkID": "AVD-KCV-0001",
              "description": "Disable anonymous requests to the API server.",
              "messages": [
                "Disable anonymous requests to the API server."
              ],
              "severity": "MEDIUM",
              "success": false,
              "target": "kube-system/pod-kube-apiserver-kind-control-plane",
              "title": "Ensure that the --anonymous-auth argument is set to false"
            }
          ],
          "description": "Control checks whether anonymous-auth is unset",
          "id": "7.0",
          "name": "Make sure anonymous-auth is unset",
          "severity": "CRITICAL"
        },
        {
          "checks": [
            {
              "checkID": "",
              "severity": "",
              "success": true
            }
          ],
          "description": "Control check whether RBAC permission is in use",
          "id": "7.1",
          "name": "Make sure -authorization-mode=RBAC",
          "severity": "CRITICAL"
        },
        {
          "checks": [
            {
              "checkID": "",
              "severity": "",
              "success": true
            }
          ],
          "description": "Control check whether audit policy is configure",
          "id": "8.0",
          "name": "Audit policy is configure (Manual)",
          "severity": "HIGH",
          "status": "FAIL"
        },
        {
          "checks": [
            {
              "category": "Kubernetes Security Check",
              "checkID": "AVD-KCV-0019",
              "description": "Enable auditing on the Kubernetes API Server and set the desired audit log path.",
              "messages": [
                "Enable auditing on the Kubernetes API Server and set the desired audit log path."
              ],
              "severity": "LOW",
              "success": false,
              "target": "kube-system/pod-kube-apiserver-kind-control-plane",
              "title": "Ensure that the --audit-log-path argument is set"
            }
          ],
          "description": "Control check whether audit log path is configure",
          "id": "8.1",
          "name": "Audit log path is configure",
          "severity": "MEDIUM"
        },
        {
          "checks": [
            {
              "category": "Kubernetes Security Check",
              "checkID": "AVD-KCV-0020",
              "description": "Retain the logs for at least 30 days or as appropriate.",
              "messages": [
                "Retain the logs for at least 30 days or as appropriate."
              ],
              "severity": "LOW",
              "success": false,
              "target": "kube-system/pod-kube-apiserver-kind-control-plane",
              "title": "Ensure that the --audit-log-maxage argument is set to 30 or as appropriate"
            }
          ],
          "description": "Control check whether audit log aging is configure",
          "id": "8.2",
          "name": "Audit log aging",
          "severity": "MEDIUM"
        }
      ],
      "title": "nsa",
      "version": "1.0"
    },
    "totalCounts": {
      "failCount": 12,
      "passCount": 15
    },
    "updateTimestamp": "2022-12-05T07:47:00Z"
  }
}

```
