## Using the Trivy Operator through Microk8s 

[Microk8s](https://microk8s.io/) is a lightweight Kubernetes distribution that can be used on your personal machine, Raspberry Pi cluster, in data centres or edge devices; just to name a few use cases.

One of the benefits of using microk8s is its add-on ecosystem. Once you have microk8s installed, you can spin up a variety of cloud native projects directly in your cluster through merely one command:

```
microk8s enable <name of the addon>
```

A list of addons is provided below.
```
    dashboard-ingress    # (community) Ingress definition for Kubernetes dashboard
    jaeger               # (community) Kubernetes Jaeger operator with its simple config
    knative              # (community) Knative Serverless and Event Driven Applications
    linkerd              # (community) Linkerd is a service mesh for Kubernetes and other frameworks
    multus               # (community) Multus CNI enables attaching multiple network interfaces to pods
    openebs              # (community) OpenEBS is the open-source storage solution for Kubernetes
    osm-edge             # (community) osm-edge is a lightweight SMI compatible service mesh for the edge-computing.
    portainer            # (community) Portainer UI for your Kubernetes cluster
    trivy-operator       # (community) Kubernetes-native security toolkit
    traefik              # (community) traefik Ingress controller for external access
    dns                  # (core) CoreDNS
    ha-cluster           # (core) Configure high availability on the current node
    helm                 # (core) Helm - the package manager for Kubernetes
    helm3                # (core) Helm 3 - the package manager for Kubernetes
    trivy                # (core) Kubernetes-native security scanner
    cert-manager         # (core) Cloud native certificate management
    dashboard            # (core) The Kubernetes dashboard
    host-access          # (core) Allow Pods connecting to Host services smoothly
    hostpath-storage     # (core) Storage class; allocates storage from host directory
    ingress              # (core) Ingress controller for external access
    kube-ovn             # (core) An advanced network fabric for Kubernetes
    mayastor             # (core) OpenEBS MayaStor
    metallb              # (core) Loadbalancer for your Kubernetes cluster
    metrics-server       # (core) K8s Metrics Server for API access to service metrics
    observability        # (core) A lightweight observability stack for logs, traces and metrics
    prometheus           # (core) Prometheus operator for monitoring and logging
    rbac                 # (core) Role-Based Access Control for authorisation
    registry             # (core) Private image registry exposed on localhost:32000
    storage              # (core) Alias to hostpath-storage add-on, deprecated
```

This tutorial will showcase how to install and then remove the Trivy Operator addon.

## Prerequisites

You need to have microk8s installed. In our case, we have set up kubectl to use the microk8s cluster. You can find different guides, depending on your operating system, on the [microk8s website.](https://microk8s.io/tutorials)

## Install the Trivy Operator 

To install the Trivy Operator, simply run the following command:
```
microk8s enable trivy
```

The confirmation should be similar to the following output:
```
Infer repository core for addon trivy
Infer repository core for addon helm3
Addon core/helm3 is already enabled
Infer repository core for addon dns
Addon core/dns is already enabled
Installing Trivy
"aqua" already exists with the same configuration, skipping
Release "trivy-operator" does not exist. Installing it now.
NAME: trivy-operator
LAST DEPLOYED: Sat Oct  8 16:39:59 2022
NAMESPACE: trivy-system
STATUS: deployed
REVISION: 1
TEST SUITE: None
NOTES:
You have installed Trivy Operator in the trivy-system namespace.
It is configured to discover Kubernetes workloads and resources in
all namespace(s).

Inspect created VulnerabilityReports by:

    kubectl get vulnerabilityreports --all-namespaces -o wide

Inspect created ConfigAuditReports by:

    kubectl get configauditreports --all-namespaces -o wide

Inspect the work log of trivy-operator by:

    kubectl logs -n trivy-system deployment/trivy-operator
Trivy is installed
```

You should now see the Trivy Operator pod running inside of the `trivy-system` namespace:
```
kubectl get all -n trivy-system
NAME                                            READY   STATUS    RESTARTS   AGE
pod/trivy-operator-57c44575c4-ml2hw             1/1     Running   0          29s
pod/scan-vulnerabilityreport-5d55f55cd7-7l6kn   1/1     Running   0          27s

NAME                     TYPE        CLUSTER-IP   EXTERNAL-IP   PORT(S)   AGE
service/trivy-operator   ClusterIP   None         <none>        80/TCP    29s

NAME                             READY   UP-TO-DATE   AVAILABLE   AGE
deployment.apps/trivy-operator   1/1     1            1           29s

NAME                                        DESIRED   CURRENT   READY   AGE
replicaset.apps/trivy-operator-57c44575c4   1         1         1       29s

NAME                                            COMPLETIONS   DURATION   AGE
job.batch/scan-vulnerabilityreport-5d55f55cd7   0/1           27s        27s
```

If you have any container images running in your microk8s cluster, Trivy will start a vulnerability scan on those right away. 

## Cleaning up

Removing the Trivy Operator from your cluster is as easy as installing it. Simply run:
```
microk8s disable trivy
```

You should see an output similar to the following:
```
Infer repository core for addon trivy
Disabling Trivy
release "trivy-operator" uninstalled
Trivy disabled
```

