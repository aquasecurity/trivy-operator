# Kubernetes InfraAssessmentReport

An instance of the InfraAssessmentReport represents checks performed by [Trivy](https://github.com/aquasecurity/trivy), 
against a Kubernetes infra core components (etcd, apiserver, scheduler, controller-manager and etc) setting and configuration.

The performed checks are based on the K8s [CIS-Benchmarks](https://www.cisecurity.org/benchmark/kubernetes) controls and more.

For example, check that api-server `Ensure that the --authorization-mode argument is not set to AlwaysAllow`.

Each report is owned by the underlying Kubernetes object and is stored in the same namespace, following the
`<workload-kind>-<workload-name>` naming convention.

The following listing shows a sample InfraAssessmentReport associated with the Pod named `kube-apiserver-minikube` in the
`kube-system` namespace.

```yaml
apiVersion: aquasecurity.github.io/v1alpha1
kind: InfraAssessmentReport
metadata:
  annotations:
    trivy-operator.aquasecurity.github.io/report-ttl: 24h0m0s
  creationTimestamp: "2022-11-08T16:27:08Z"
  generation: 1
  labels:
    plugin-config-hash: 659b7b9c46
    resource-spec-hash: 56fd79dd67
    annotation.trivy-operator.resource.kind: Pod
    annotation.trivy-operator.resource.name: kube-apiserver-minikube
    annotation.trivy-operator.resource.namespace: kube-system
  name: pod-kube-apiserver-minikube
  namespace: kube-system
  ownerReferences:
  - apiVersion: v1
    blockOwnerDeletion: false
    controller: true
    kind: Pod
    name: kube-apiserver-minikube
    uid: 60587bf5-1b24-4167-8b77-fe7fa42c0216
  resourceVersion: "11046"
  uid: 00f2214a-31c8-4e7c-b0ba-23c7ed0eec2b
report:
  checks:
  - category: Kubernetes Security Check
    checkID: KCV0020
    description: Retain the logs for at least 30 days or as appropriate.
    messages:
    - Ensure that the --audit-log-maxage argument is set to 30 or as appropriate
    severity: LOW
    success: false
    title: Ensure that the --audit-log-maxage argument is set to 30 or as appropriate
  - category: Kubernetes Security Check
    checkID: KCV0010
    description: Limit the rate at which the API server accepts requests.
    messages:
    - Ensure that the admission control plugin EventRateLimit is set
    severity: LOW
    success: false
    title: Ensure that the admission control plugin EventRateLimit is set
  - category: Kubernetes Security Check
    checkID: KCV0047
    description: Do not use self-signed certificates for TLS.
    messages:
    - ""
    severity: LOW
    success: true
    title: Ensure that the --peer-auto-tls argument is not set to true
  - category: Kubernetes Security Check
    checkID: KCV0046
    description: etcd should be configured for peer authentication.
    messages:
    - ""
    severity: LOW
    success: true
    title: Ensure that the --peer-client-cert-auth argument is set to true
  - category: Kubernetes Security Check
    checkID: KCV0024
    description: Validate service account before validating token.
    messages:
    - ""
    severity: LOW
    success: true
    title: Ensure that the --service-account-lookup argument is set to true
  - category: Kubernetes Security Check
    checkID: KCV0041
    description: Do not bind the scheduler service to non-loopback insecure addresses.
    messages:
    - ""
    severity: LOW
    success: true
    title: Ensure that the --bind-address argument is set to 127.0.0.1
  - category: Kubernetes Security Check
    checkID: KCV0013
    description: The SecurityContextDeny admission controller can be used to deny
      pods which make use of some SecurityContext fields which could allow for privilege
      escalation in the cluster. This should be used where PodSecurityPolicy is not
      in place within the cluster.
    messages:
    - Ensure that the admission control plugin SecurityContextDeny is set if PodSecurityPolicy
      is not used
    severity: LOW
    success: false
    title: Ensure that the admission control plugin SecurityContextDeny is set if
      PodSecurityPolicy is not used
  - category: Kubernetes Security Check
    checkID: KCV0006
    description: Verify kubelet's certificate before establishing connection.
    messages:
    - Ensure that the --kubelet-certificate-authority argument is set as appropriate
    severity: LOW
    success: false
    title: Ensure that the --kubelet-certificate-authority argument is set as appropriate
  - category: Kubernetes Security Check
    checkID: KCV0019
    description: Enable auditing on the Kubernetes API Server and set the desired
      audit log path.
    messages:
    - Ensure that the --audit-log-path argument is set
    severity: LOW
    success: false
    title: Ensure that the --audit-log-path argument is set
  - category: Kubernetes Security Check
    checkID: KCV0021
    description: Retain 10 or an appropriate number of old log files.
    messages:
    - Ensure that the --audit-log-maxbackup argument is set to 10 or as appropriate
    severity: LOW
    success: false
    title: Ensure that the --audit-log-maxbackup argument is set to 10 or as appropriate
  - category: Kubernetes Security Check
    checkID: KCV0015
    description: Reject creating objects in a namespace that is undergoing termination.
    messages:
    - ""
    severity: LOW
    success: true
    title: Ensure that the admission control plugin NamespaceLifecycle is set
  - category: Kubernetes Security Check
    checkID: KCV0008
    description: Restrict kubelet nodes to reading only objects associated with them.
    messages:
    - ""
    severity: LOW
    success: true
    title: Ensure that the --authorization-mode argument includes Node
  - category: Kubernetes Security Check
    checkID: KCV0017
    description: Do not disable the secure port.
    messages:
    - ""
    severity: LOW
    success: true
    title: Ensure that the --secure-port argument is not set to 0
  - category: Kubernetes Security Check
    checkID: KCV0030
    description: Encrypt etcd key-value store.
    messages:
    - ""
    severity: LOW
    success: true
    title: Ensure that the --encryption-provider-config argument is set as appropriate
  - category: Kubernetes Security Check
    checkID: KCV0034
    description: Disable profiling, if not needed.
    messages:
    - ""
    severity: LOW
    success: true
    title: Ensure that the --profiling argument is set to false
  - category: Kubernetes Security Check
    checkID: KCV0007
    description: Do not always authorize all requests.
    messages:
    - ""
    severity: LOW
    success: true
    title: Ensure that the --authorization-mode argument is not set to AlwaysAllow
  - category: Kubernetes Security Check
    checkID: KCV0009
    description: Turn on Role Based Access Control.
    messages:
    - ""
    severity: LOW
    success: true
    title: Ensure that the --authorization-mode argument includes RBAC
  - category: Kubernetes Security Check
    checkID: KCV0038
    description: Enable kubelet server certificate rotation on controller-manager.
    messages:
    - ""
    severity: LOW
    success: true
    title: Ensure that the RotateKubeletServerCertificate argument is set to true
  - category: Kubernetes Security Check
    checkID: KCV0014
    description: Automate service accounts management.
    messages:
    - ""
    severity: LOW
    success: true
    title: Ensure that the admission control plugin ServiceAccount is set
  - category: Kubernetes Security Check
    checkID: KCV0040
    description: Disable profiling, if not needed.
    messages:
    - ""
    severity: LOW
    success: true
    title: Ensure that the --profiling argument is set to false
  - category: Kubernetes Security Check
    checkID: KCV0022
    description: Rotate log files on reaching 100 MB or as appropriate.
    messages:
    - Ensure that the --audit-log-maxsize argument is set to 100 or as appropriate
    severity: LOW
    success: false
    title: Ensure that the --audit-log-maxsize argument is set to 100 or as appropriate
  - category: Kubernetes Security Check
    checkID: KCV0003
    description: This admission controller rejects all net-new usage of the Service
      field externalIPs.
    messages:
    - ""
    severity: LOW
    success: true
    title: Ensure that the --DenyServiceExternalIPs is not set
  - category: Kubernetes Security Check
    checkID: KCV0044
    description: Do not use self-signed certificates for TLS.
    messages:
    - ""
    severity: LOW
    success: true
    title: Ensure that the --auto-tls argument is not set to true
  - category: Kubernetes Security Check
    checkID: KCV0039
    description: Do not bind the scheduler service to non-loopback insecure addresses.
    messages:
    - ""
    severity: LOW
    success: true
    title: Ensure that the --bind-address argument is set to 127.0.0.1
  - category: Kubernetes Security Check
    checkID: KCV0005
    description: Enable certificate based kubelet authentication.
    messages:
    - ""
    severity: LOW
    success: true
    title: Ensure that the --kubelet-client-certificate and --kubelet-client-key arguments
      are set as appropriate
  - category: Kubernetes Security Check
    checkID: KCV0042
    description: Configure TLS encryption for the etcd service.
    messages:
    - ""
    severity: LOW
    success: true
    title: Ensure that the --cert-file and --key-file arguments are set as appropriate
  - category: Kubernetes Security Check
    checkID: KCV0018
    description: Disable profiling, if not needed.
    messages:
    - Ensure that the --profiling argument is set to false
    severity: LOW
    success: false
    title: Ensure that the --profiling argument is set to false
  - category: Kubernetes Security Check
    checkID: KCV0025
    description: Explicitly set a service account public key file for service accounts
      on the apiserver.
    messages:
    - ""
    severity: LOW
    success: true
    title: Ensure that the --service-account-key-file argument is set as appropriate
  - category: Kubernetes Security Check
    checkID: KCV0135
    description: Use individual service account credentials for each controller.
    messages:
    - ""
    severity: LOW
    success: true
    title: Ensure that the --use-service-account-credentials argument is set to true
  - category: Kubernetes Security Check
    checkID: KCV0043
    description: Enable client authentication on etcd service.
    messages:
    - ""
    severity: LOW
    success: true
    title: Ensure that the --client-cert-auth argument is set to true
  - category: Kubernetes Security Check
    checkID: KCV0028
    description: Setup TLS connection on the API server.
    messages:
    - Ensure that the --client-ca-file argument is set as appropriate
    severity: LOW
    success: false
    title: Ensure that the --client-ca-file argument is set as appropriate
  - category: Kubernetes Security Check
    checkID: KCV0004
    description: Use https for kubelet connections.
    messages:
    - ""
    severity: LOW
    success: true
    title: Ensure that the --kubelet-https argument is set to true
  - category: Kubernetes Security Check
    checkID: KCV0045
    description: etcd should be configured to make use of TLS encryption for peer
      connections.
    messages:
    - ""
    severity: LOW
    success: true
    title: Ensure that the --peer-cert-file and --peer-key-file arguments are set
      as appropriate
  - category: Kubernetes Security Check
    checkID: KCV0033
    description: Activate garbage collector on pod termination, as appropriate.
    messages:
    - ""
    severity: LOW
    success: true
    title: Ensure that the --terminated-pod-gc-threshold argument is set as appropriate
  - category: Kubernetes Security Check
    checkID: KCV0011
    description: Do not allow all requests.
    messages:
    - ""
    severity: LOW
    success: true
    title: Ensure that the admission control plugin AlwaysAdmit is not set
  - category: Kubernetes Security Check
    checkID: KCV0002
    description: Do not use token based authentication.
    messages:
    - ""
    severity: LOW
    success: true
    title: Ensure that the --token-auth-file parameter is not set
  - category: Kubernetes Security Check
    checkID: KCV0001
    description: Disable anonymous requests to the API server.
    messages:
    - Ensure that the --anonymous-auth argument is set to false
    severity: MEDIUM
    success: false
    title: Ensure that the --anonymous-auth argument is set to false
  - category: Kubernetes Security Check
    checkID: KCV0016
    description: Limit the Node and Pod objects that a kubelet could modify.
    messages:
    - ""
    severity: LOW
    success: true
    title: Ensure that the admission control plugin NodeRestriction is set
  - category: Kubernetes Security Check
    checkID: KCV0029
    description: etcd should be configured to make use of TLS encryption for client
      connections.
    messages:
    - Ensure that the --etcd-cafile argument is set as appropriate
    severity: LOW
    success: false
    title: Ensure that the --etcd-cafile argument is set as appropriate
  - category: Kubernetes Security Check
    checkID: KCV0027
    description: Setup TLS connection on the API server.
    messages:
    - ""
    severity: LOW
    success: true
    title: Ensure that the --tls-cert-file and --tls-private-key-file arguments are
      set as appropriate
  - category: Kubernetes Security Check
    checkID: KCV0026
    description: etcd should be configured to make use of TLS encryption for client
      connections.
    messages:
    - ""
    severity: LOW
    success: true
    title: Ensure that the --etcd-certfile and --etcd-keyfile arguments are set as
      appropriate
  - category: Kubernetes Security Check
    checkID: KCV0036
    description: Explicitly set a service account private key file for service accounts
      on the controller manager.
    messages:
    - ""
    severity: LOW
    success: true
    title: Ensure that the --service-account-private-key-file argument is set as appropriate
  - category: Kubernetes Security Check
    checkID: KCV0037
    description: Allow pods to verify the API server's serving certificate before
      establishing connections.
    messages:
    - ""
    severity: LOW
    success: true
    title: Ensure that the --root-ca-file argument is set as appropriate
  scanner:
    name: Trivy
    vendor: Aqua Security
    version: dev
  summary:
    criticalCount: 0
    highCount: 0
    lowCount: 10
    mediumCount: 1

```

