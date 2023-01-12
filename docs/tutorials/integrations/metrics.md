# Metrics

`trivy-operator` exposed a `/metrics` endpoint by default  with metrics for vulnerabilities, exposed secrets,rbacassessment and configaudits.

## Report Summary

### Vunerability

A report summary series exposes the count of checks of each status reported in a given `VulnerabilityReport`. For example:

```shell
trivy_image_vulnerabilities{
    image_digest="",image_registry="index.docker.io",image_repository="rancher/coredns-coredns",image_tag="1.8.3",name="replicaset-coredns-6488c6fcc6-coredns",namespace="kube-system",severity="High"
    } 10
```

### ConfigAudit

A report summary series exposes the count of checks of each status reported in a given `ConfigAuditReport`. For example:

```shell
trivy_resource_configaudits{
    name="daemonset-svclb-traefik",namespace="kube-system",severity="High"
    } 2
```

### RbacAssessments

A report summary series exposes the count of checks of each status reported in a given `RbacAssessmentsReport`. For example:

```shell
trivy_role_rbacassessments{
    name="role-6fbccbcb9d",namespace="kube-system",severity="Medium"
    } 1
```

### ExposedsSecrets

A report summary series exposes the count of checks of each status reported in a given `ExposedsSecretsReport`. For example:

```shell
trivy_image_exposedsecrets{
    image_digest="",image_registry="index.docker.io",image_repository="josedonizetti/trivy",image_tag="secrettest",name="pod-tt-reg-test",namespace="default",severity="Critical"
    } 1
```

### InfraAssessments

A report summary series exposes the count of checks of each status reported in a given `InfraAssessmentsReport`. For example:

```shell
trivy_resource_infraassessments{
    name="pod-kube-controller-manager-minikube",namespace="kube-system",severity="Low"
    } 3
```

### ClusterComplianceReport

A report summary series exposes the count of checks of each status reported in a given `ClusterComplianceReport`. For example:

```shell
trivy_cluster_compliance{description="National Security Agency - Kubernetes Hardening Guidance",status="Fail",title="nsa"} 12
trivy_cluster_compliance{description="National Security Agency - Kubernetes Hardening Guidance",status="Pass",title="nsa"} 17
```

## Vulnerability ID

Exposing vulnerability ID on metrics by settting the EnvVar: `OPERATOR_METRICS_VULN_ID_ENABLED" envDefault:"false"`

```shell
trivy_vulnerability_id{
    class="os-pkgs",image_digest="",image_registry="index.docker.io",image_repository="library/nginx",image_tag="1.16.1",installed_version="5.3.28+dfsg1-0.5",name="replicaset-nginx-deployment-559d658b74-nginx",namespace="default",package_type="debian",resource="libdb5.3",severity="Critical",vuln_id="CVE-2019-8457"
} 1
```

## Adding Custom Label to Metrics

User might wants to include custom labels to resource that can be exposed and associated with the Prometheus metrics.
this capbility can be added by setting the following helm param.

Example:

`--set="trivyOperator.reportResourceLabels": "owner"`

`k8s_label_` prefix wil be added to custom label

```shell
trivy_resource_configaudits{k8s_label_owner="platform",name="daemonset-svclb-traefik",namespace="kube-system",severity="Critical"} 2
```
