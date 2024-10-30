# Troubleshooting the Trivy Operator

The Trivy Operator installs several Kubernetes resources into your Kubernetes cluster.

Here are the common steps to check whether the operator is running correctly and to troubleshoot common issues.

In addition to this section, you might want to check [issues](https://github.com/aquasecurity/trivy/issues), [discussion forum](https://github.com/aquasecurity/trivy/discussions), or [Slack](https://slack.aquasec.com) to see if someone from the community had similar problems before.

Also note that Trivy Operator is based on existing Aqua OSS project - [Starboard](https://github.com/aquasecurity/starboard), and shares some of the design, principles and code with it. Existing content that relates to Starboard Operator might also be relevant for Trivy Operator, and Starboard's [issues](https://github.com/aquasecurity/starboard/issues), [discussion forum](https://github.com/aquasecurity/starboard/discussions), or [Slack](https://slack.aquasec.com) might also be interesting to check.  
In some cases you might want to refer to [Starboard's Design documents](https://aquasecurity.github.io/starboard/latest/design/).

## Installation

Make sure that the latest version of the Trivy Operator is installed. For this, have a look at the installation [options.](./helm.md)

For instance, if your are using the Helm deployment, you need to check the Helm Chart version deployed to your cluster. You can check the Helm Chart version with the following command:
```
helm list -n trivy-system
```

## Operator Pod Not Running

The Trivy Operator will run a pod inside your cluster. If you have followed the installation guide, you will have installed the Operator to the `trivy-system`.

Make sure that the pod is in the `Running` status:
```
kubectl get pods -n trivy-system
```

This is how it will look if it is running okay:

```
NAMESPACE            NAME                                         READY   STATUS    RESTARTS      AGE
trivy-system     trivy-operator-6c9bd97d58-hsz4g          1/1     Running   5 (19m ago)   30h
```

If the pod is in `Failed`, `Pending`, or `Unknown` state check the events and the logs of the pod.

First, check the events, since they might be more descriptive of the problem. However, if the events do not give a clear reason why the pod cannot spin up, then you want to check the logs, which provide more detail.

```
kubectl describe pod <POD-NAME> -n trivy-system
```

To check the logs, use the following command:
```
kubectl logs deployment/trivy-operator -n trivy-system
```

If your pod is not running, try to look for errors as they can give an indication on the problem.

If there are too many logs messages, try deleting the Trivy pod and observe its behavior upon restarting. A new pod should spin up automatically after deleting the failed pod.

## ImagePullBackOff or ErrImagePull

Check the status of the Trivy Operator pod running inside of your Kubernetes cluster. If the Status is ImagePullBackOff or ErrImagePull, it means that the Operator either

* tries to access the wrong image
* cannot pull the image from the registry

Make sure that you are providing the right resources upon installing the Trivy Operator.

## CrashLoopBackOff

If your pod is in `CrashLoopBackOff`, it is likely the case that the pod cannot be scheduled on the Kubernetes node that it is trying to schedule on.
In this case, you want to investigate further whether there is an issue with the node. It could for instance be the case that the node does not have sufficient resources.

## Reconciliation Error

It could happen that the pod appears to be running normally but does not reconcile the resources inside of your Kubernetes cluster.

Check the logs for Reconciliation errors:
```
kubectl logs deployment/trivy-operator -n trivy-system
```

If this is the case, the Trivy Operator likely does not have the right configurations to access your resource.

## Operator does not create VulnerabilityReports

VulnerabilityReports are owned and controlled by the immediate Kubernetes workload. Every VulnerabilityReport of a pod is thus, linked to a [ReplicaSet.](./index.md) In case the Trivy Operator does not create a VulnerabilityReport for your workloads, it could be that it is not monitoring the namespace that your workloads are running on.

An easy way to check this is by looking for the `ClusterRoleBinding` for the Trivy Operator:

```
kubectl get ClusterRoleBinding | grep "trivy-operator"
```

Alternatively, you could use the `kubectl-who-can` [plugin by Aqua](https://github.com/aquasecurity/kubectl-who-can):

```console
$ kubectl who-can list vulnerabilityreports
No subjects found with permissions to list vulnerabilityreports assigned through RoleBindings

CLUSTERROLEBINDING                           SUBJECT                         TYPE            SA-NAMESPACE
cluster-admin                                system:masters                  Group
trivy-operator                           trivy-operator              ServiceAccount  trivy-system
system:controller:generic-garbage-collector  generic-garbage-collector       ServiceAccount  kube-system
system:controller:namespace-controller       namespace-controller            ServiceAccount  kube-system
system:controller:resourcequota-controller   resourcequota-controller        ServiceAccount  kube-system
system:kube-controller-manager               system:kube-controller-manager  User
```

If the `ClusterRoleBinding` does not exist, Trivy currently cannot monitor any namespace outside of the `trivy-system` namespace.

For instance, if you are using the [Helm Chart](./helm.md), you want to make sure to set the `targetNamespace` to the namespace that you want the Operator to monitor.

The operator also could not be configured to scan the workload you are expecting. Check to make sure `OPERATOR_TARGET_WORKLOADS` is set correctly in your configuration. This allows you to specify which workload types to be scanned. 

For example, by default in the [Helm Chart](./helm.md) values, the following Kubernetes workloads are configured to be scanned
`"pod,replicaset,replicationcontroller,statefulset,daemonset,cronjob,job"`.


## Installing the Operator in a namespace with default deny-all egress/ingress network policies

If you are trying to install the Trivy-Operator in a namespace where there are default deny-all egress/ingress network policies (see example below), you might need to configure some extra network policies yourself to make sure the traffic can flow as expected and the operator does not enter an error state.

```yaml
---
kind: NetworkPolicy
metadata:
  name: default-deny-egress
  namespace: trivy-system
spec:
  podSelector: {}
  policyTypes:
  - Egress
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: trivy-system
spec:
  podSelector: {}
  policyTypes:
  - Ingress
```

Notice how the namespace is `trivy-system`, the above network policies are assuming that you installed the `trivy-operator` (and `trivy-server` when applicable) there. Keep in mind these same network policies might be part of other namespaces (like kube-system or default) where important Kubernetes components live, such as the coredns and/or the default Kubernetes service.

We'll now create a namespace where we will deploy our pod with vulnerabilities. This namespace will be called *applications*

`kubectl create namespace applications`

Next step is to create the pod with vulnerabilities. To do this we can run the following command:

`kubectl run nginx -n applications`

At this point, we should expect the Trivy Operator to generate the `VulnerabilityReports` custom resources in our `applications` namespace. However, if we try to get these resources across the `applications` namespace, we'll see that we won't get any reports:

```sh
kubectl get vulnerabilityreports -n applications
No resources found in applications namespace.
```

If we look at the `get pods` command, the description of the trivy-operator pod and its logs, we'll see some interesting messages that will help us understand why the reports aren't being generated.

```sh
kubectl get pods -n trivy-system
NAME                              READY   STATUS             RESTARTS        AGE
trivy-operator-846f8c6446-clzlk   0/1     CrashLoopBackOff   6 (2m41s ago)   8m28s
```

```sh
kubectl describe pods trivy-operator-846f8c6446-clzlk -n trivy-system | grep Events -A 10
Events:
  Type     Reason     Age                    From               Message
  ----     ------     ----                   ----               -------
  Normal   Scheduled  7m11s                  default-scheduler  Successfully assigned trivy-system/trivy-operator-846f8c6446-clzlk to k3d-kon-test-server-0
  Normal   Created    6m26s (x4 over 7m11s)  kubelet            Created container trivy-operator
  Normal   Started    6m26s (x4 over 7m11s)  kubelet            Started container trivy-operator
  Normal   Pulled     5m38s (x5 over 7m11s)  kubelet            Container image "ghcr.io/aquasecurity/trivy-operator:0.16.4" already present on machine
  Warning  BackOff    2m4s (x32 over 7m9s)   kubelet            Back-off restarting failed container trivy-operator in pod trivy-operator-846f8c6446-clzlk_trivy-system(ddbfdf6d-751b-4137-860e-5561c71b6f8d)
```

The pod is in a `CrashLoopBackOff` state, and the description confirms that the container is constantly being restarted.

```sh
kubectl logs trivy-operator-846f8c6446-clzlk -n trivy-system
2023/11/21 06:04:02 maxprocs: Leaving GOMAXPROCS=2: CPU quota undefined
{"level":"info","ts":"2023-11-21T06:04:02Z","logger":"main","msg":"Starting operator","buildInfo":{"Version":"0.16.4","Commit":"c2f0e0f4f773f090f61c07489fd6dc062d465b2d","Date":"2023-10-29T08:18:47Z","Executable":""}}
{"level":"info","ts":"2023-11-21T06:04:02Z","logger":"operator","msg":"Resolved install mode","install mode":"AllNamespaces","operator namespace":"trivy-system","target namespaces":[],"exclude namespaces":"","target workloads":["pod","replicaset","replicationcontroller","statefulset","daemonset","cronjob","job"]}
{"level":"info","ts":"2023-11-21T06:04:02Z","logger":"operator","msg":"Watching all namespaces"}
unable to run trivy operator: failed getting configmap: trivy-operator: Get "https://10.43.0.1:443/api/v1/namespaces/trivy-system/configmaps/trivy-operator": dial tcp 10.43.0.1:443: connect: connection refused
```

We see that the trivy-operator is correctly configured to watch all namespaces, that means that the `VulnerabilityReports` should be generated across all namespaces, including the `applications` namespace.

The first red flag that something is wrong with the networking configuration can be found in the following message:

```sh
unable to run trivy operator: failed getting configmap: trivy-operator: Get "https://10.43.0.1:443/api/v1/namespaces/trivy-system/configmaps/trivy-operator": dial tcp 10.43.0.1:443: connect: connection refused
```

The IP address in context `10.43.0.1` belongs to the kube-api. We can confirm so by looking for the service called `kubernetes`:

```sh
kubectl get svc kubernetes
NAME         TYPE        CLUSTER-IP   EXTERNAL-IP   PORT(S)   AGE
kubernetes   ClusterIP   10.43.0.1    <none>        443/TCP   28d
```

Basically, the trivy-operator cannot reach the kube-api to execute the calls looking for different resources. In example above, we can see that the trivy-operator was looking for the trivy-operator configmap in the trivy-system. Our first task will be to enable traffic between the trivy-operator pods and the kube-api service so that the trivy-operator can successfully get what it needs from the kube-api.

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-egress-from-trivy-system-to-kube-api
  namespace: trivy-system
spec:
  podSelector: {}
  egress:
  - to:
    - ipBlock:
        cidr: 10.43.0.1/32
```

If we run `kubectl logs -n trivy-system deployment/trivy-operator`, we'll see that the error referncing `10.43.0.1:443` has disappeared. This means that we have successfully enabled all outbound traffic between the trivy-system namespace and the kube-api.

NOTE: For faster results, restart the trivy-operator deployment:

```sh
kubectl rollout restart deployment trivy-operator -n trivy-system
```

We also notice that there are new errors as part of the logs referencing port `53`:

```sh
failed to download vulnerability DB: database download error: OCI repository error: 1 error occurred:\n\t* Get \"https://ghcr.io/v2/\": dial tcp: lookup ghcr.io on 10.43.0.10:53:
```

This means that the trivy-operator cannot resolve DNS records. The cause of this is the fact that the traffic to the `kube-dns` service residing in the `kube-system` namespace is disabled because of the `deny-all` egress network policies in the `trivy-system` namespace. We can confirm this by running the following command and to the svc information:

```sh
kubectl get svc -n kube-system kube-dns
NAME       TYPE        CLUSTER-IP   EXTERNAL-IP   PORT(S)                  AGE
kube-dns   ClusterIP   10.43.0.10   <none>        53/UDP,53/TCP,9153/TCP   20m
```

To remediate this issue, we'll need to create a network policy allowing traffic on port `53` to the `kube-system` namespace. This will allow the trivy-systems to perforn DNS lookups via the `core-dns` pods. 

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-egress-allow-kube-system-dns
  namespace: trivy-system
spec:
  egress:
    - ports:
        - port: 53
          protocol: TCP
        - port: 53
          protocol: UDP
      to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
  podSelector: {}
  policyTypes:
    - Egress
```

When we look at the trivy-operator logs again, we'll see that the error logs referencing the port `53` are gone. Now we see a new error mentioning port `443`:

```sh
{"level":"error","ts":"2024-02-25T07:46:25Z","logger":"reconciler.scan job","msg":"Scan job container","job":"trivy-system/scan-vulnerabilityreport-57ff7d8c55","container":"1bad6981-ddcb-4845-98cd-e8bb5b25926c","status.reason":"Error","status.message":"2024-02-25T07:46:22.300Z\t\u001b[34mINFO\u001b[0m\tNeed to update DB\n2024-02-25T07:46:22.300Z\t\u001b[34mINFO\u001b[0m\tDB Repository: ghcr.io/aquasecurity/trivy-db\n2024-02-25T07:46:22.300Z\t\u001b[34mINFO\u001b[0m\tDownloading DB...\n2024-02-25T07:46:22.816Z\t\u001b[31mFATAL\u001b[0m\tinit error: DB error: failed to download vulnerability DB: database download error: oci download error: failed to fetch the layer: Get \"https://pkg-containers.githubusercontent.com/ghcr1/blobs/sha256:2f0f866f6f274de192d9dfcd752c892e2099126fe0362dc8b4c7bb0b7e75956d?se=2024-02-25T07%3A55%3A00Z&sig=r9L1Phopnozwr%2B5TOTj8tF7D7bixyUqdsJNDESU1TPI%3D&sp=r&spr=https&sr=b&sv=2019-12-12\": dial tcp 185.199.111.154:443: connect: connection refused\n"
```

This means that the trivy-operator cannot talk to the internet over port 443 to download the vulnerability database. We need to create a new network policy to allow this exception.

Before proceeding with the creation of our next network policy, it is important to understand a few things. Trivy-operator itself does not download the vulnerability database. Instead, it spawns a couple of scan pods generated via a job that download the vulnerability database over port `443`.

We can confirm this by doing a `watch kubectl get pods -n trivy-system` on pods on the trivy-system, then restarting the trivy-operator via `kubectl rollout restart deployment -n trivy-system`:

```sh
NAME                                        READY   STATUS    RESTARTS   AGE
trivy-operator-6b4dc78c5-nzzcm              1/1     Running   0          11s
scan-vulnerabilityreport-6f9cb46645-pzx7w   1/1     Running   0          8s
```

Here we see the scanning pod being spawned. We now must get a good label so we can create a network policy for it. We do so by grabbing the pod name and getting the labels via `yq` while we watch for the pod in another terminal.

```sh
kubectl get pods -n trivy-system scan-vulnerabilityreport-6dfb8dc69f-fwpbh -o yaml | yq '.metadata.labels'
```

We get the output:

```sh
app.kubernetes.io/managed-by: trivy-operator
controller-uid: 10aba790-6ee6-4802-81ed-ad77908ea10d
job-name: scan-vulnerabilityreport-6dfb8dc69f
resource-spec-hash: 764dd688f
annotation.trivy-operator.resource.kind: ReplicaSet
annotation.trivy-operator.resource.name: trivy-operator-6b65576869
annotation.trivy-operator.resource.namespace: trivy-system
vulnerabilityReport.scanner: Trivy
```

We can probably use `app.kubernetes.io/managed-by: trivy-operator`, as this is a label in a standard format Kubernetes recommends.

We proceed to create the network policy as follows:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-egress-443-trivy-operator
  namespace: trivy-system
spec:
  egress:
    - ports:
        - port: 443
          protocol: TCP
      to:
        - ipBlock:
            cidr: 0.0.0.0/0
  podSelector:
    matchLabels:
      app.kubernetes.io/managed-by: trivy-operator
  policyTypes:
    - Egress
```

We use the CIDR `0.0.0.0/0` to denote that we want to allow the target pods to talk to any IP address, and we specify port `443` as the allowed port. If we query for the logs again, we'll see that the error is gone. Moreover, if we do a `kubectl get vulnerabilityreport -n applications`, we'll see that the report for the `nginx` pod has been recently generated:

```sh
NAME              REPOSITORY      TAG      SCANNER   AGE
pod-nginx-nginx   library/nginx   latest   Trivy     2m28s
```

### Trivy-server

When deploying the trivy-operator + trivy-server for downloading the vulnerability database, you will need to create similar network policies to the ones created for the trivy-operator as a standalone component.
After installing trivy-server in the current cluster, the pod entered a status of `CrashLookBackOff`. Upon inspecting the logs, for the trivy-server statefulset, we counter the following error:

```sh
2024-02-28T04:53:50.195Z	FATAL	failed to download vulnerability DB: database download error: OCI repository error: 1 error occurred:
  * Get "https://ghcr.io/v2/": dial tcp 140.82.114.34:443: connect: connection refused
```

This means that the trivy-server cannot connect to the image registry over port `443`. This can be fixed by applying a network policy like `allow-egress-443-trivy-operator`, which we created for the trivy-operator, but first we must get the label that will be used to select the pods that the trivy-server generates. We do so by doing a `kubectl get pods trivy-0 -n trivy-system --show-labels`, we obtain the following output:

```sh
NAME      READY   STATUS    RESTARTS   AGE     LABELS
trivy-0   1/1     Running   0          3m40s   app.kubernetes.io/instance=trivy,app.kubernetes.io/name=trivy,controller-revision-hash=trivy-7494747496,statefulset.kubernetes.io/pod-name=trivy-0
```

We can make use of the label `app.kubernetes.io/name=trivy`, so the resulting network policy will look like this:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-egress-443-trivy-server
  namespace: trivy-system
spec:
  egress:
    - ports:
        - port: 443
          protocol: TCP
      to:
        - ipBlock:
            cidr: 0.0.0.0/0
  podSelector:
    matchLabels:
      app.kubernetes.io/name: trivy
  policyTypes:
    - Egress
```

We proceed to restart the trivy-server statefulset with `kubectl rollout restart sts -n trivy-system trivy` and see that the error previously seen is gone. Trivy-server was able to download the DB and is listening on port `4954`.

```sh
kubectl logs -n trivy-system statefulset/trivy
2024-02-28T05:17:53.590Z	INFO	Need to update DB
2024-02-28T05:17:53.590Z	INFO	DB Repository: ghcr.io/aquasecurity/trivy-db
2024-02-28T05:17:53.590Z	INFO	Downloading DB...
2024-02-28T05:17:57.550Z	INFO	Listening 0.0.0.0:4954...
```

When we restart the trivy-operator to test if everything works as it should, we realize that it is outputting the following error via the logs:

```sh
failed to do request: Post \"http://trivy.trivy-system:4954/twirp/trivy.cache.v1.Cache/MissingBlobs\": dial tcp 10.43.158.111:4954: connect: connection refused"
```

The trivy-operator has to reach out to the trivy-server on port `4954` in order to access the downloaded vulnerability database. We also need to enable that connection via a networkpolicy (you guessed it), we can delete the previously created network policy `allow-egress-443-trivy-operator` via `kubectl delete networkpolicy allow-egress-443-trivy-operator -n trivy-system` and create a new one with a new name that mentions port `4954` to also allow egress traffic to port `4954` and rename it to something that reflects its new purpose. Last, but not least:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-egress-443-and-4954-trivy-operator
  namespace: trivy-system
spec:
  egress:
    - ports:
        - port: 443
          protocol: TCP
        - port: 4954
          protocol: TCP
      to:
        - ipBlock:
            cidr: 0.0.0.0/0
  podSelector:
    matchLabels:
      app.kubernetes.io/managed-by: trivy-operator
  policyTypes:
    - Egress
```

After having saved the changes to the policy, we can proceed and restart the trivy-operator `kubectl rollout restart deployment trivy-operator -n trivy-system
`. When looking at the logs for the trivy-operator, we see that there are some errors indicating it still cannot connect to port `4954`:

```sh
dial tcp 10.43.158.111:4954: connect: connection refused
```

So far we have created network policies to allow egress traffic. There is one last missing network policy and it is of type ingress. This network policy will allow the trivy-server to receive traffic on port `4954`.

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-ingress-4954-trivy-server
  namespace: trivy-system
spec:
  ingress:
    - ports:
        - port: 4954
          protocol: TCP
  podSelector:
    matchLabels:
      app.kubernetes.io/name: trivy
  policyTypes:
    - Ingress
```

This network policy uses the appropiate `matchLabels` to only target the trivy-server. When restarting the trivy-operator with `kubectl rollout restart deployment trivy-operator -n trivy-system`, we see that the errors are gone. When doing a `kubectl get vulnerabilityreport -n applications`, we see that there is a newly generated `vulnerabilityreport` for our `nginx` pod:

```sh
NAME              REPOSITORY      TAG      SCANNER   AGE
pod-nginx-nginx   library/nginx   latest   Trivy     12s
```

We have successfully added all the necessary network policies for our trivy-operator to work on client/server mode.