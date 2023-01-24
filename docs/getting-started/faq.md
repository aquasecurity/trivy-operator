# Frequently Asked Questions

## Why do you duplicate instances of VulnerabilityReports for the same image digest?

Docker image reference is not a first class citizen in Kubernetes. It's a
property of the container definition. Trivy-operator relies on label selectors to
associate VulnerabilityReports with corresponding Kubernetes workloads, not
particular image references. For example, we can get all reports for the
wordpress Deployment with the following command:

```text
kubectl get vulnerabilityreports \
  -l trivy-operator.resource.kind=Deployment \
  -l trivy-operator.resource.name=wordpress
```

Beyond that, for each instance of the VulnerabilityReports we set the owner
reference pointing to the corresponding pods controller. By doing that we can
manage orphaned VulnerabilityReports and leverage Kubernetes garbage collection.
For example, if the `wordpress` Deployment is deleted, all related
VulnerabilityReports are automatically garbage collected.

## Why do you create an instance of the VulnerabilityReport for each container?
The idea is to partition VulnerabilityReports generated for a particular
Kubernetes workload by containers is to mitigate the risk of exceeding the etcd
request payload limit. By default, the payload of each Kubernetes object stored
etcd is subject to 1.5 MiB.

## How can you export reporst from within the Kubernetes cluster?

The Trivy Operator is a Kubernetes-based tool. Meaning, it does not provide a platform out of the box through which you could export and download security reports.
The Trivy Operator creates the Kubernetes CRD as report for each security scan and stores it inside your Kubernetes cluster. You can then either query reports directly from within your cluster or use other tools in the CNCF ecosystem or enterprise tools to access the reports.

Have a look at our [tutorial on using Prometheus and Grafana](../tutorials/grafana-dashboard.md) with our Grafana Dashboard to access the Trivy Operator report metrics. 

## How can you configure the report format for trivy-operator? For example to convert to CSV or Serif formats.

The only way is to use an external tool to convert it to csv from yaml/json or you could try to leverage the integration with postee sending it to an external system (mail, webhook and etc).
