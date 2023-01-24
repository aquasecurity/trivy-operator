# Configuration

You can configure Trivy-Operator to control it's behavior and adapt it to your needs. Aspects of the operator machinery are configured using environment variables on the operator Pod, while aspects of the scanning behavior are controlled by ConfigMaps and Secrets.

# Operator Configuration Settings

Trivy Operator read configuration settings from ConfigMaps, as well as Secrets that holds
confidential settings (such as a GitHub token). Trivy-Operator plugins read configuration and secret data from ConfigMaps
and Secrets named after the plugin. For example, Trivy configuration is stored in the ConfigMap and Secret named
`trivy-operator-trivy-config`.

You can change the default settings with `kubectl patch` or `kubectl edit` commands. For example, by default Trivy
displays vulnerabilities with all severity levels (`UNKNOWN`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`). However, you can
display only `HIGH` and `CRITICAL` vulnerabilities by patching the `trivy.severity` value in the `trivy-operator-trivy-config`
ConfigMap:

```
TRIVY_OPERATOR_NAMESPACE=<your trivy operator namespace>
```
```
kubectl patch cm trivy-operator-trivy-config -n $TRIVY_OPERATOR_NAMESPACE \
  --type merge \
  -p "$(cat <<EOF
{
  "data": {
    "trivy.severity": "HIGH,CRITICAL"
  }
}
EOF
)"
```

To set the GitHub token used by Trivy add the `trivy.githubToken` value to the `trivy-operator-trivy-config` Secret:

```
TRIVY_OPERATOR_NAMESPACE=<your trivy opersator namespace>
GITHUB_TOKEN=<your token>
```
```
kubectl patch secret trivy-operator-trivy-config -n $TRIVY_OPERATOR_NAMESPACE \
  --type merge \
  -p "$(cat <<EOF
{
  "data": {
    "trivy.githubToken": "$(echo -n $GITHUB_TOKEN | base64)"
  }
}
EOF
)"
```

The following table lists available settings with their default values. Check plugins' documentation to see
configuration settings for common use cases. For example, switch Trivy from [Standalone] to [ClientServer] mode.

| CONFIGMAP KEY                                                        | DEFAULT                               | DESCRIPTION                                                                                                                                                                                                                         |
|------------------------------------------------|---------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `vulnerabilityReports.scanner`                                       | `Trivy`                               | The name of the plugin that generates vulnerability reports. Either `Trivy` or `Aqua`.                                                                                                                                              |
| `vulnerabilityReports.scanJobsInSameNamespace`                       | `"false"`                             | Whether to run vulnerability scan jobs in same namespace of workload. Set `"true"` to enable.                                                                                                                                       |
| `configAuditReports.scanner`                                         | `Trivy`                               | The name of the plugin that generates config audit reports.                                                                                                                                                                         |
| `scanJob.tolerations`                                                | N/A                                   | JSON representation of the [tolerations] to be applied to the scanner pods so that they can run on nodes with matching taints. Example: `'[{"key":"key1", "operator":"Equal", "value":"value1", "effect":"NoSchedule"}]'`           |
| `scanJob.nodeSelector`                                                | N/A                                   | JSON representation of the [nodeSelector] to be applied to the scanner pods so that they can run on nodes with matching labels. Example: `'{"example.com/node-type":"worker", "cpu-type": "sandylake"}'`           |
| `scanJob.annotations`                                                 | N/A                                   | One-line comma-separated representation of the annotations which the user wants the scanner pods to be annotated with. Example: `foo=bar,env=stage` will annotate the scanner pods with the annotations `foo: bar` and `env: stage` |
| `scanJob.templateLabel`                                               | N/A                                   | One-line comma-separated representation of the template labels which the user wants the scanner pods to be labeled with. Example: `foo=bar,env=stage` will labeled the scanner pods with the labels `foo: bar` and `env: stage`     |
| `scanJob.podTemplatePodSecurityContext`                               | N/A                                   | One-line JSON representation of the template securityContext which the user wants the scanner pods to be secured with. Example: `{"RunAsUser": 1000, "RunAsGroup": 1000, "RunAsNonRoot": true}`                |
| `scanJob.podTemplateContainerSecurityContext`                         | N/A| One-line JSON representation of the template securityContext which the user wants the scanner containers (and their initContainers) to be amended with. Example: `{"allowPrivilegeEscalation": false, "capabilities": { "drop": ["ALL"]},"privileged": false, "readOnlyRootFilesystem": true }`|
| `compliance.failEntriesLimit`                                         | `"10"`                                | Limit the number of fail entries per control check in the cluster compliance detail report.                                                                                                                                         |
| `scanJob.compressLogs       `                                       | `"true"`                              | Control whether scanjob output should be compressed                                                                                                                                    |

!!! tip
    You can delete a configuration key.For example, the following `kubectl patch` command deletes the `trivy.httpProxy` key:
    ```
    TRIVY_OPERATOR_NAMESPACE=<your trivy operator namespace>
    ```
    ```
    kubectl patch cm trivy-operator-trivy-config -n $TRIVY_OPERATOR_NAMESPACE \
      --type json \
      -p '[{"op": "remove", "path": "/data/trivy.httpProxy"}]'
    ```

[ClientServer]: ../../docs/vulnerability-scanning/trivy.md#clientserver
[tolerations]: https://kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration


# Operator Configuration

| NAME                                                         | DEFAULT                | DESCRIPTION                                                                                                                                                                                                  |
|--------------------------------------------------------------|------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `OPERATOR_NAMESPACE`                                         | N/A                    | See [Install modes](#install-modes)                                                                                                                                                                          |
| `OPERATOR_TARGET_NAMESPACES`                                 | N/A                    | See [Install modes](#install-modes)                                                                                                                                                                          |
| `OPERATOR_EXCLUDE_NAMESPACES`                                | N/A                    | A comma separated list of namespaces (or glob patterns) to be excluded from scanning in all namespaces [Install mode](#install-modes).                                                                       |
 | `OPERATOR_TARGET_WORKLOADS`                                  | All workload resources | A comma separated list of Kubernetes workloads to be included in the vulnerability and config-audit scans                                                                                                    |
| `OPERATOR_SERVICE_ACCOUNT`                                   | `trivy-operator`       | The name of the service account assigned to the operator's pod                                                                                                                                               |
| `OPERATOR_LOG_DEV_MODE`                                      | `false`                | The flag to use (or not use) development mode (more human-readable output, extra stack traces and logging information, etc).                                                                                 |
| `OPERATOR_SCAN_JOB_TIMEOUT`                                  | `5m`                   | The length of time to wait before giving up on a scan job                                                                                                                                                    |
| `OPERATOR_CONCURRENT_SCAN_JOBS_LIMIT`                        | `10`                   | The maximum number of scan jobs create by the operator                                                                                                                                                       |
| `OPERATOR_SCAN_JOB_RETRY_AFTER`                              | `30s`                  | The duration to wait before retrying a failed scan job                                                                                                                                                       |
| `OPERATOR_BATCH_DELETE_LIMIT`                                | `10`                   | The maximum number of config audit reports deleted by the operator when the plugin's config has changed.                                                                                                     |
| `OPERATOR_BATCH_DELETE_DELAY`                                | `10s`                  | The duration to wait before deleting another batch of config audit reports.                                                                                                                                  |
| `OPERATOR_METRICS_BIND_ADDRESS`                              | `:8080`                | The TCP address to bind to for serving [Prometheus][prometheus] metrics. It can be set to `0` to disable the metrics serving.                                                                                |
| `OPERATOR_HEALTH_PROBE_BIND_ADDRESS`                         | `:9090`                | The TCP address to bind to for serving health probes, i.e. `/healthz/` and `/readyz/` endpoints.                                                                                                             |
| `OPERATOR_VULNERABILITY_SCANNER_ENABLED`                     | `true`                 | The flag to enable vulnerability scanner                                                                                                                                                                     |
| `OPERATOR_CONFIG_AUDIT_SCANNER_ENABLED`                      | `false`                | The flag to enable configuration audit scanner                                                                                                                                                               |
| `OPERATOR_RBAC_ASSESSMENT_SCANNER_ENABLED`                   | `true`                 | The flag to enable rbac assessment scanner                                                                                                                                                                   |
| `OPERATOR_CONFIG_AUDIT_SCANNER_SCAN_ONLY_CURRENT_REVISIONS`  | `true`                 | The flag to enable config audit scanner to only scan the current revision of a deployment                                                                                                                    |
| `OPERATOR_CONFIG_AUDIT_SCANNER_BUILTIN`                      | `true`                 | The flag to enable built-in configuration audit scanner                                                                                                                                                      |
| `OPERATOR_VULNERABILITY_SCANNER_SCAN_ONLY_CURRENT_REVISIONS` | `true`                 | The flag to enable vulnerability scanner to only scan the current revision of a deployment                                                                                                                   |
| `OPERATOR_ACCESS_GLOBAL_SECRETS_SERVICE_ACCOUNTS`            | `true`                 | The flag to enable access to global secrets/service accounts to allow `vulnerability scan job` to pull images from private registries  
| `OPERATOR_SCANNER_REPORT_TTL`                                | `"24h"`                | The flag to set how long a report should exist. When a old report is deleted a new one will be created by the controller. It can be set to `""` to disabled the TTL for vulnerability scanner. |
| `OPERATOR_LEADER_ELECTION_ENABLED`                           | `false`                | The flag to enable operator replica leader election                                                                                                                                                          |
| `OPERATOR_LEADER_ELECTION_ID`                                | `trivy-operator-lock`  | The name of the resource lock for leader election                                                                                                                                                            |
| `OPERATOR_EXPOSED_SECRET_SCANNER_ENABLED`                    | `true`                 | The flag to enable exposed secret scanner                                                                                                                                                                    |
| `OPERATOR_WEBHOOK_BROADCAST_URL`                             | `""`                   | The flag to enable operator reports to be sent to a webhook endpoint. "" means that this feature is disabled                                                                                                 |
| `OPERATOR_BUILT_IN_TRIVY_SERVER`                             | `false`                | The flag enable the usage of built-in trivy server in cluster ,its also overwrite the following trivy params with built-in values trivy.mode = ClientServer and serverURL = http://[server Service Name].[trivy Operator Namespace]:4975
| `OPERATOR_WEBHOOK_BROADCAST_TIMEOUT`                         | `30s`                  | The flag to set operator webhook timeouts, if webhook broadcast is enabled                                                                                                                                   |
| `OPERATOR_PRIVATE_REGISTRY_SCAN_SECRETS_NAMES`               | `{}`                   | The flag to provide information about names of the secrets for different namespaces to use them for authentication in private registries if there are no imagePullSecrets in Service Accounts and/or in Pod's Spec                                                                                                                                   |
| `OPERATOR_MERGE_RBAC_FINDING_WITH_CONFIG_AUDIT`              | `false`                | The flag to enable merging rbac finding with config-audit report


The values of the `OPERATOR_NAMESPACE` and `OPERATOR_TARGET_NAMESPACES` determine the install mode, which in turn determines the multitenancy support of the operator.


| MODE| OPERATOR_NAMESPACE | OPERATOR_TARGET_NAMESPACES | DESCRIPTION|
|---|---|---|---|
| OwnNamespace| `operators`| `operators`| The operator can be configured to watch events in the namespace it is deployed in.                             |
| SingleNamespace| `operators`| `foo`| The operator can be configured to watch for events in a single namespace that the operator is not deployed in. |
| MultiNamespace| `operators`| `foo,bar,baz`| The operator can be configured to watch for events in more than one namespace.                                 |
| AllNamespaces| `operators`| (blank string)| The operator can be configured to watch for events in all namespaces.|

## Example - configure namespaces to scan

To change the target namespace from all namespaces to the `default` namespace edit the `trivy-operator` Deployment and change the value of the `OPERATOR_TARGET_NAMESPACES` environment variable from the blank string (`""`) to the `default` value.

# Scanning configuration

| CONFIGMAP KEY| DEFAULT| DESCRIPTION                                                                                                                                                                                                                                                                                     |
|---|---|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `vulnerabilityReports.scanner`| `Trivy`| The name of the plugin that generates vulnerability reports. Either `Trivy` or `Aqua`.                                                                                                                                                                                                          |
| `vulnerabilityReports.scanJobsInSameNamespace` | `"false"`| Whether to run vulnerability scan jobs in same namespace of workload. Set `"true"` to enable.                                                                                                                                                                                                   |
| `scanJob.tolerations`| N/A| JSON representation of the [tolerations] to be applied to the scanner pods so that they can run on nodes with matching taints. Example: `'[{"key":"key1", "operator":"Equal", "value":"value1", "effect":"NoSchedule"}]'`                                                                       |
| `scanJob.nodeSelector`| N/A| JSON representation of the [nodeSelector] to be applied to the scanner pods so that they can run on nodes with matching labels. Example: `'{"example.com/node-type":"worker", "cpu-type": "sandylake"}'`                                                                                        |
| `scanJob.automountServiceAccountToken`         | `"false"`   | the flag to enable automount for service account token on scan job. Set `"true"` to enable.                                                                                                                                                                                                     |
| `scanJob.annotations`| N/A| One-line comma-separated representation of the annotations which the user wants the scanner pods to be annotated with. Example: `foo=bar,env=stage` will annotate the scanner pods with the annotations `foo: bar` and `env: stage`                                                             |
| `scanJob.templateLabel`| N/A| One-line comma-separated representation of the template labels which the user wants the scanner pods to be labeled with. Example: `foo=bar,env=stage` will labeled the scanner pods with the labels `foo: bar` and `env: stage`                                                                 |
| `scanJob.podTemplatePodSecurityContext`| N/A| One-line JSON representation of the template securityContext which the user wants the scanner pods to be secured with. Example: `{"RunAsUser": 1000, "RunAsGroup": 1000, "RunAsNonRoot": true}`                                                                                                 |
| `scanJob.podTemplateContainerSecurityContext`| N/A| One-line JSON representation of the template securityContext which the user wants the scanner containers (and their initContainers) to be amended with. Example: `{"allowPrivilegeEscalation": false, "capabilities": { "drop": ["ALL"]},"privileged": false, "readOnlyRootFilesystem": true }` |
| `report.resourceLabels`| N/A| One-line comma-separated representation of the scanned resource labels which the user wants to include in the Prometheus metrics report. Example: `owner,app,tier`|
| `metrics.resourceLabelsPrefix`| `k8s_label`| Prefix that will be prepended to the labels names indicated in `report.ResourceLabels` when including them in the Prometheus metrics|
|`report.recordFailedChecksOnly`| `"true"`| this flag is to record only failed checks on misconfiguration reports (config-audit and rbac assessment)
| `skipResourceByLabels`| N/A| One-line comma-separated labels keys which trivy-operator will skip scanning on resources with matching labels. Example: `test,transient`|

## Example - patch ConfigMap

By default Trivy displays vulnerabilities with all severity levels (`UNKNOWN`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`). To display only `HIGH` and `CRITICAL` vulnerabilities by patching the `trivy.severity` value in the `trivy-operator-trivy-config` ConfigMap:

```bash
kubectl patch cm trivy-operator-trivy-config -n trivy-system \
  --type merge \
  -p "$(cat <<EOF
{
  "data": {
    "trivy.severity": "HIGH,CRITICAL"
  }
}
EOF
)"
```

## Example - patch Secret

To set the GitHub token used by Trivy scanner add the `trivy.githubToken` value to the `trivy-operator-trivy-config` Secret:

```bash
kubectl patch secret trivy-operator-trivy-config -n trivy-system \
  --type merge \
  -p "$(cat <<EOF
{
  "data": {
    "trivy.githubToken": "$(echo -n <your token> | base64)"
  }
}
EOF
)"
```

## Example - delete a key

The following `kubectl patch` command deletes the `trivy.httpProxy` key:

```bash
kubectl patch cm trivy-operator-trivy-config -n trivy-system \
  --type json \
  -p '[{"op": "remove", "path": "/data/trivy.httpProxy"}]'
```

[tolerations]: https://kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration


[prometheus]: https://github.com/prometheus

## Configuring the Trivy Operator Helm Chart

The values outlined above are set through the [values.yaml](https://github.com/aquasecurity/trivy-operator/blob/main/deploy/helm/values.yaml) file in the [Trivy Operator Helm Chart.](https://github.com/aquasecurity/trivy-operator/tree/main/deploy/helm)
If you wish to make any changes to the Helm Chart, please create a new values.yaml file locally and adapt the configuration that you want to change.

For instance, if you want to install the Trivy Operator with `ignoreunfixed` set to true, you would write the following fields into your values.yaml file:

```
trivy:
  ignoreUnfixed: true
```

Note: Make sure that you are not setting the values but also within the field of the operator that the value applies to e.g. in the above example `ignoreUnfixed` is a field in `trivy`/

Once you have defined the values.yaml file, you can install the Helm Chart withe you specific configuration:

```
helm install trivy-operator aqua/trivy-operator \
  --namespace trivy-system \
  --create-namespace \
  --values values.yaml
```

Please refer to the Helm [installation guide](./helm.md) for the exact command.

