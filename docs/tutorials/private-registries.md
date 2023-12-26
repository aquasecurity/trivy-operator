# Allow the Trivy Operator to access private registries

In this tutorial, we will detail multiple ways on setting up the Trivy Operator to access and scan container images from private container registries.

## Prerequisites

To follow this tutorial, you need the following installed on your machine:

- The Helm CLI tool
- kubectl and connected to a running Kubernetes cluster
- a container images in a private registy, running as a pod inside your cluster

Note that we will be using a local Kubernetes KinD cluster and a private container image stored on a private GitHub repository for the examples.

## First Option: Filesystem Scanning

For this tutorial, we will use the [Operator Helm Chart.](https://aquasecurity.github.io/trivy-operator/latest/operator/installation/helm/)

The configuration options for the Helm Chart can be found in the [values.yaml](https://github.com/aquasecurity/trivy-operator/blob/main/deploy/helm/values.yaml) manifest.
Navigate to the section `Trivy.command`. The default will be:

```
trivy:
# command. One of `image`, `filesystem` or `rootfs` scanning, depending on the target type required for the scan.
  # For 'filesystem' and `rootfs` scanning, ensure that the `trivyOperator.scanJobPodTemplateContainerSecurityContext` is configured
  # to run as the root user (runAsUser = 0).
  command: image
```

By default, the command that trivy is supposed to run inside your cluster is `trivy image` for container image scanning. However, we want to change it to scan the filesystem in your nodes instead. Container images are ultimately stored as files on the node level of your cluster. This way, trivy is going to scan the files of your container images for vulnerabilities. This is a little bit of a work-around with the downside that the Trivy Operator will have to run as root. However, remember that security scanning already requires the operator to have lots of cluster privileges.

Next, we will change the the `command` and the `trivyOperator.scanJobPodTemplateContainerSecurityContext`of the `values.yaml` manifest. For this, we can create a new values.yaml manifest with our desired modifications:

```sh
trivy:
    command: filesystem
    ignoreUnfixed: true
trivyOperator:
    scanJobPodTemplateContainerSecurityContext:
        # For filesystem scanning, Trivy needs to run as the root user
        runAsUser: 0
```

Lastly, we can deploy the operator inside our cluster with referencing our new `values.yaml` manifest to override the default values:

```sh
helm upgrade --install trivy-operator aqua/trivy-operator \
  --namespace trivy-system \
  --create-namespace \
  --version {{ var.chart_version }}
  --values ./values.yaml
```

Alternatively, it is possible to set the values directly through Helm instead of referencing an additional `values.yaml` file:

```sh
helm upgrade --install trivy-operator aqua/trivy-operator \
  --namespace trivy-system \
  --create-namespace \
  --version {{ var.chart_version }}
  --set="trivy.command=fs"
  --set="trivyOperator.scanJobPodTemplateContainerSecurityContext.runAsUser=0"
```

Once installed, make sure that

1. the operator is running in your cluster
2. the operator has created a VulnerabilityReport for the container image from the private registry

```sh
❯ kubectl get deployment -n trivy-system

NAME             READY   UP-TO-DATE   AVAILABLE   AGE
trivy-operator   1/1     1            1           99s
```

## Second Option: Using an ImagePullSecret to access containers from the Private Registry

Note that you might be using an ImagePullSecret already to allow pods to pull the container images from a private registry.

To set-up an ImagePullSecret, we first need an access token to our private registry. For GitHub private registries, you can create a new access token under the [following link.](https://github.com/settings/tokens/new) In comparison, the official Kubernetes documentation shows how to create the [ImagePullSecret for the DockerHub.](https://kubernetes.io/docs/tasks/configure-pod-container/pull-image-private-registry/)

Next, we will base64 encode the access token:

```sh
echo -n "YOUR_GH_ACCOUNT_NAME:YOUR_TOKEN" | base64
```

And take the output of the previous command and parse it into the following to base64 encode it again:

```sh
echo -n  '{"auths":{"ghcr.io":{"auth":"OUTPUT"}}}' | base64
```

Lastly, we are going to store the output in a Kubernetes Secret YAML manifest:

`imagepullsecret.yaml`

```yaml
kind: Secret
type: kubernetes.io/dockerconfigjson
apiVersion: v1
metadata:
  name: dockerconfigjson-github-com
  labels:
    app: app-name
data:
  .dockerconfigjson: OUTPUT
```

Note that base64 encoding is not encryption, thust, you should not commit this file. If you are looking to store secrets in Kubernetes, have a look at e.g. [Hashicorp Secret Vault](https://www.vaultproject.io/use-cases/kubernetes), or with an [External Secrets Operator (ESO)](https://youtu.be/SyRZe5YVCVk).

Make sure to reference the ImagePullSecret in your container `spec`:

```sh
containers:
- name: cns-website
  image: ghcr.io/account-name/image-id:tag
imagePullSecrets:
- name: dockerconfigjson-github-com
```

And finally, we can apply the secret to the same namespace as our application:

```sh
kubectl apply -f imagepullsecret.yaml -n app
```

If you have to modify your deployment.yaml manifest, make sure to update that as well.

Once you have defined your ImagePullSecret, the Operator will have access to the container image automatically with the defaul configuration.

## Third Option: Define an ImagePullSecret through a ServiceAccount

Alternatively to defining an ImagePullSecret on the pod level, we can also define the secret through a Kubernetes Service Account. Our workload will be associated with the service account and can pull the secret from our private registry.
Similar to the `Second Option`, once we have the key associated to our workload, the Trivy operator scan job has access to the secret and can pull the image.

Again, you can have a look at the official [Kubernetes documentation](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/) for further details.

`imagepullsecret.yaml`

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: dockerconfigjson-sa-github-com
  annotations:
    kubernetes.io/service-account.name: cns-website
type: kubernetes.io/dockerconfigjson
data:
  .dockerconfigjson: OUTPUT
```

`serviceaccount.yaml`

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: cns-website
imagePullSecrets:
- name: dockerconfigjson-sa-github-com
```

`deployment.yaml`
*or where you have defined your container

```yaml
spec:
    containers:
    - name: cns-website
      image: ghcr.io/account-name/image-id:tag
    serviceAccountName: cns-website
```

## Fourth Option: Define Secrets through Trivy-Operator configuration

If there are no ImagePullSecret on pod or Service Account level (for example, valid credentials are placed in container runtime configuration) you can add them in Trivy-Operator configuration.

It's very similar to `Second Option`. First of all you need to create a secret. To do it, we first need an access token to our private registry. For GitHub private registries, you can create a new access token under the [following link.](https://github.com/settings/tokens/new) In comparison, the official Kubernetes documentation shows how to create the [ImagePullSecret for the DockerHub.](https://kubernetes.io/docs/tasks/configure-pod-container/pull-image-private-registry/)

Next, we will base64 encode the access token:

```sh
echo -n "YOUR_GH_ACCOUNT_NAME:YOUR_TOKEN" | base64
```

And take the output of the previous command and parse it into the following to base64 encode it again:

```sh
echo -n  '{"auths":{"ghcr.io":{"auth":"OUTPUT"}}}' | base64
```

Lastly, we are going to store the output in a Kubernetes Secret YAML manifest:

`imagepullsecret.yaml`

```yaml
kind: Secret
type: kubernetes.io/dockerconfigjson
apiVersion: v1
metadata:
  name: dockerconfigjson-github-com
  labels:
    app: app-name
data:
  .dockerconfigjson: OUTPUT
```

Note that base64 encoding is not encryption, thust, you should not commit this file. If you are looking to store secrets in Kubernetes, have a look at e.g. [Hashicorp Secret Vault](https://www.vaultproject.io/use-cases/kubernetes), or with an [External Secrets Operator (ESO)](https://youtu.be/SyRZe5YVCVk).

And finally, we can apply the secret to the same namespace as our application:

```sh
kubectl apply -f imagepullsecret.yaml -n app
```

Next, we will change the `privateRegistryScanSecretsNames` of the `values.yaml` manifest. For this, we can create a new `values.yaml` manifest with our desired modification. We need to provide desired namespace and secret name. In our example they are `app` and `dockerconfigjson-github-com` accordingly.

```sh
operator:
    privateRegistryScanSecretsNames: {"app":"dockerconfigjson-github-com"}
```

If you want you can add additional namespaces and secret names to `privateRegistryScanSecretsNames` separated by comma.

Lastly, we can deploy the operator inside our cluster with referencing our new `values.yaml` manifest to override the default values:

```sh
helm upgrade --install trivy-operator aqua/trivy-operator \
  --namespace trivy-system \
  --create-namespace \
  --version {{ var.chart_version }}
  --values ./values.yaml
```

Alternatively, it is possible to set the values directly through Helm instead of referencing an additional `values.yaml` file:

```sh
helm upgrade --install trivy-operator aqua/trivy-operator \
  --namespace trivy-system \
  --create-namespace \
  --version {{ var.chart_version }}
  --set-json='operator.privateRegistryScanSecretsNames={"app":"dockerconfigjson-github-com"}'
```

Works only with helm 3.10+, because `--set-json` flag was added in 3.10.0. Otherwise you can use `values.yaml` instead.

Once installed, make sure that

1. the operator is running in your cluster
2. the operator has created a VulnerabilitReport for the container image from the private registry

```
❯ kubectl get deployment -n trivy-system

NAME             READY   UP-TO-DATE   AVAILABLE   AGE
trivy-operator   1/1     1            1           99s
```

## Fifth Option: configure gcr service account json

this option is similar to forth option but using gcr json_key for gcr service account and creating a secret

```sh
echo -n "_json_key:{
  "type": "service_account",
  "project_id": "test",
  "private_key_id": "3adas34asdas34wadad",
  "private_key": "-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----\n",
  "client_email": "<test@test.iam.gserviceaccount.com>",
  "client_id": "34324234324324",
  "auth_uri": "<https://accounts.google.com/o/oauth2/auth>",
  "token_uri": "<https://oauth2.googleapis.com/token>",
  "auth_provider_x509_cert_url": "<https://www.googleapis.com/oauth2/v1/certs>",
  "client_x509_cert_url": "<https://www.googleapis.com/robot/v1/metadata/x509/test-gcr-f5dh3h5g%40test.iam.gserviceaccount.com>"
}" | base64
```

And take the output of the previous command and parse it into the following to base64 encode it again:

```sh
echo -n '{"auths":{"us.gcr.io":{"auth":"OUTPUT"}}}' | base64
```

Lastly, we are going to store the output in a Kubernetes Secret YAML manifest:

`gcr_secret.yaml`

```yaml
kind: Secret
type: kubernetes.io/dockerconfigjson
apiVersion: v1
metadata:
  name: dockerconfigjson-github-com
  labels:
    app: app-name
data:
  .dockerconfigjson: OUTPUT
```

## Sixth Option: Grant access through managed registries

The last way that you could give the Trivy operator access to your private container registry is through managed registries. In this case, the container registry and your Kubernetes cluster would have to be on the same cloud provider; then you can define access to your container namespace as part of the IAM account. Once defined, trivy will already have the permissions for the registry.

For additional information, please refer to the [documentation on managed registries.](https://aquasecurity.github.io/trivy-operator/v0.18.0-rc/docs/vulnerability-scanning/managed-registries/)
