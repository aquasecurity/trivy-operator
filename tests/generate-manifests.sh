#!/usr/bin/env bash
SCRIPT_ROOT=$(dirname "${BASH_SOURCE[0]}")/..
echo $SCRIPT_ROOT
CRD_DIR=$SCRIPT_ROOT/deploy/crd
HELM_DIR=$SCRIPT_ROOT/deploy/helm
TEST_DIR=$SCRIPT_ROOT/tests
CLIENT_SERVER_DIR=$SCRIPT_ROOT/tests/e2e/client-server/manifests
FS_DIR=$SCRIPT_ROOT/tests/e2e/fs-mode/manifests
IMAGE_DIR=$SCRIPT_ROOT/tests/e2e/image-mode/manifests
STATIC_DIR=$SCRIPT_ROOT/deploy/static

HELM_TMPDIR=$(mktemp -d)
trap "rm -rf $HELM_TMPDIR" EXIT

function createOperator ()
{
  local folder=$1
# generate operating configure to fs scanning 

cat $CRD_DIR/* > $folder/trivy-operator.yaml

### if ns.yaml do not exist, cat namespace.yaml to trivy-operator.yaml (avoid duplicate namespace definition)
[ ! -f $HELM_TMPDIR/trivy-operator/templates/ns.yaml ] && cat $STATIC_DIR/namespace.yaml >> $folder/trivy-operator.yaml

rm -rf $HELM_TMPDIR/trivy-operator/templates/specs
cat $HELM_TMPDIR/trivy-operator/templates/* >> $folder/trivy-operator.yaml
rm -rf $HELM_TMPDIR
} 

# create operator for fs mode
helm template trivy-operator $HELM_DIR \
  --namespace trivy-system \
  --set="managedBy=kubectl" \
  --set="trivy.command=filesystem" \
  --set="trivyOperator.scanJobPodTemplateContainerSecurityContext.runAsUser=0" \
  --set="trivy.ignoreUnfixed=true" \
  --set="excludeNamespaces=trivy-system\,kube-system\,kube-public\,local-path-storage\,kube-node-lease" \
  --set="image.repository=ghcr.io/aquasecurity/trivy-operator" \
  --set="image.tag=nightly" \
  --output-dir=$HELM_TMPDIR

createOperator $FS_DIR 

# create operator for client-server mode
helm template trivy-operator $HELM_DIR \
  --namespace trivy-system \
  --set="managedBy=kubectl" \
  --set="operator.builtInTrivyServer=true" \
  --set="trivy.ignoreUnfixed=true" \
  --set="excludeNamespaces=trivy-system\,kube-system\,kube-public\,local-path-storage\,kube-node-lease" \
  --set="image.repository=ghcr.io/aquasecurity/trivy-operator" \
  --set="image.tag=nightly" \
  --output-dir=$HELM_TMPDIR

createOperator $CLIENT_SERVER_DIR 

# create operator for image mode
helm template trivy-operator $HELM_DIR \
  --namespace trivy-system \
  --set="managedBy=kubectl" \
  --set="trivy.ignoreUnfixed=true" \
  --set="excludeNamespaces=trivy-system\,kube-system\,kube-public\,local-path-storage\,kube-node-lease" \
  --set="image.repository=ghcr.io/aquasecurity/trivy-operator" \
  --set="image.tag=nightly" \
  --output-dir=$HELM_TMPDIR

  createOperator $IMAGE_DIR 