# Metrics

`trivy-operator` exposed a `/metrics` endpoint by default  with metrics for vulnerabilities, exposed secrets,rbacassessment and configaudits.

## Report Summary

### Vunerability

A report summary series exposes the count of checks of each status reported in a given `VulnerabilityReport`. For example:

```shell
trivy_image_vulnerabilities{
    container_name="coredns",image_digest="",image_registry="index.docker.io",image_os_eosl="",image_os_family="",image_os_name="",image_repository="rancher/coredns-coredns",image_tag="1.8.3",name="replicaset-coredns-6488c6fcc6-coredns",namespace="kube-system",resource_kind="ReplicaSet",resource_name="coredns-6488c6fcc6",severity="High"
    } 10
```

### ConfigAudit

A report summary series exposes the count of checks of each status reported in a given `ConfigAuditReport`. For example:

```shell
trivy_resource_configaudits{
    name="daemonset-svclb-traefik",namespace="kube-system",resource_kind="DaemonSet",resource_name="svclb-traefik",severity="High"
    } 2
```

### ConfigAuditInfo

Exposes details about ConfigAudit that were discovered in images, enable by setting the EnvVar: `OPERATOR_METRICS_CONFIG_AUDIT_INFO_ENABLED" envDefault:"false"` . For example:

```shell
trivy_configaudits_info{
    config_audit_category="car1 category for config audit",config_audit_description="car1 description for config audit",config_audit_id="car1 Id",config_audit_success="false",config_audit_title="car1 config audit title",name="replicaset-nginx-6d4cf56db6",namespace="default",resource_kind="ReplicaSet",resource_name="nginx-6d4cf56db6",severity="Critical"} 1
```

### RbacAssessments

A report summary series exposes the count of checks of each status reported in a given `RbacAssessmentsReport`. For example:

```shell
trivy_role_rbacassessments{
    name="role-6fbccbcb9d",namespace="kube-system",resource_kind="Role",resource_name="6fbccbcb9d",severity="Medium"
    } 1
```

### RbacAssessmentsInfo

Exposes details about RbacAssessments that were discovered in images, enable by setting the EnvVar: `OPERATOR_METRICS_RBAC_ASSESSMENT_INFO_ENABLED" envDefault:"false"` . For example:

```shell
trivy_rbacassessments_info{
    name="role-admin-6d4cf56db6",namespace="default",rbac_assessment_category="car1 category for rbac assessment",rbac_assessment_description="car1 description for rbac assessment",rbac_assessment_id="car1 Id",rbac_assessment_success="true",rbac_assessment_title="car1 rbac assessment title",resource_kind="Role",resource_name="admin-6d4cf56db6",severity="Critical"} 1
```

### ExposedsSecrets

A report summary series exposes the count of checks of each status reported in a given `ExposedsSecretsReport`. For example:

```shell
trivy_image_exposedsecrets{
    container_name="trivy",image_digest="",image_registry="index.docker.io",image_repository="josedonizetti/trivy",image_tag="secrettest",name="pod-tt-reg-test",namespace="default",resource_kind="Pod",resource_name="tt-reg-test",severity="Critical"
    } 1
```

### ExposedsSecretsInfo

Exposes details about secrets that were discovered in images, enable by setting the EnvVar: `OPERATOR_METRICS_EXPOSED_SECRET_INFO_ENABLED" envDefault:"false"` . For example:

```shell
trivy_exposedsecrets_info{
    container_name="trivy",image_digest="",image_registry="index.docker.io",image_repository="josedonizetti/trivy",image_tag="secrettest",name="pod-tt-reg-test",namespace="default",resource_kind="Pod",resource_name="tt-reg-test",secret_category="AWS",secret_rule_id="aws-access-key-id",secret_target="/etc/apt/s3auth.conf",secret_title="AWS Access Key ID",severity="Critical"
    } 1
```

### InfraAssessments

A report summary series exposes the count of checks of each status reported in a given `InfraAssessmentsReport`. For example:

```shell
trivy_resource_infraassessments{
    name="pod-kube-controller-manager-minikube",namespace="kube-system",resource_kind="Pod",resource_name="kube-controller-manager-minikube",severity="Low"
    } 3
```

### InfraAssessmentsInfo

```shell
Exposes details about InfraAssessments that were discovered in images, enable by setting the EnvVar: `OPERATOR_METRICS_INFRA_ASSESSMENT_INFO_ENABLED" envDefault:"false"` . For example:

```shell

trivy_infraassessments_info{
    name="pod-kube-apiserver-minikube-6d4cf56db6",namespace="kube-system",infra_assessment_category="car1 category for infra assessment",infra_assessment_description="car1 description for infra assessment",infra_assessment_id="car1 Id",infra_assessment_success="true",infra_assessment_title="car1 infra assessment title",resource_kind="Pod",resource_name="kube-apiserver-minikube-6d4cf56db6",severity="Critical"
    } 1
```

### ClusterComplianceReport

A report summary series exposes the count of checks of each status reported in a given `ClusterComplianceReport`. For example:

```shell
trivy_cluster_compliance{description="National Security Agency - Kubernetes Hardening Guidance",status="Fail",title="nsa"} 12
trivy_cluster_compliance{description="National Security Agency - Kubernetes Hardening Guidance",status="Pass",title="nsa"} 17
```

### ClusterComplianceInfo

Exposes details about ClusterCompliance that were discovered in images, enable by setting the EnvVar: `OPERATOR_METRICS_CLUSTER_COMPLIANCE_INFO_ENABLED" envDefault:"false"` . For example:

```shell
trivy_compliance_info{compliance_id="car1 Id",compliance_name="car1 cluster compliance name",
    description="National Security Agency - Kubernetes Hardening Guidance",severity="MEDIUM",status="Fail",title="nsa"} 1
trivy_compliance_info{compliance_id="car1 Id",compliance_name="car1 cluster compliance name",
    description="National Security Agency - Kubernetes Hardening Guidance",severity="LOW",status="Pass",title="nsa"} 1
```

## Vulnerability ID

Exposing vulnerability ID on metrics by setting the EnvVar: `OPERATOR_METRICS_VULN_ID_ENABLED" envDefault:"false"`

```shell
trivy_vulnerability_id{
    class="os-pkgs",container_name="nginx",fixed_version="",image_digest="",image_registry="index.docker.io",image_repository="library/nginx",image_tag="1.16.1",installed_version="5.3.28+dfsg1-0.5",last_modified_date="2023-06-28T21:16:00Z",name="replicaset-nginx-deployment-559d658b74-nginx",namespace="default",package_type="debian",pkg_path="/app/local",published_date="2023-06-28T21:15:00Z",resource="libdb5.3",resource_kind="ReplicaSet",resource_name="nginx-deployment-559d658b74",severity="Critical",vuln_id="CVE-2019-8457",vuln_score="7.5",vuln_title="sqlite: heap out-of-bound read in function rtreenode()"
} 1
```

## Adding Custom Label to Metrics

User might wants to include custom labels to resource that can be exposed and associated with the Prometheus metrics.
this capability can be added by setting the following helm param.

Example:

`--set="trivyOperator.reportResourceLabels": "owner"`

`k8s_label_` prefix will be added to custom label

```shell
trivy_resource_configaudits{k8s_label_owner="platform",name="daemonset-svclb-traefik",namespace="kube-system",resource_kind="DaemonSet",resource_name="svclb-traefik",severity="Critical"} 2
```
