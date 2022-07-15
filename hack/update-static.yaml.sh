#!/usr/bin/env bash

SCRIPT_ROOT=$(dirname "${BASH_SOURCE[0]}")/..

HELM_DIR=$SCRIPT_ROOT/deploy/helm
STATIC_DIR=$SCRIPT_ROOT/deploy/static

cp $STATIC_DIR/apiextensions.k8s.io_v1_customresourcedefinition_* $HELM_DIR/crds/
cp $STATIC_DIR/rbac.authorization.k8s.io_v1_clusterrole_trivy-operator.yaml $HELM_DIR/generated/
sed -si '1s/^/---\n/' $HELM_DIR/crds/* $HELM_DIR/generated/* $STATIC_DIR/v1_namespace_trivy-system.yaml

HELM_TMPDIR=$(mktemp -d)
trap "rm -rf $HELM_TMPDIR" EXIT

helm template trivy-operator $HELM_DIR \
  --namespace trivy-system \
  --set="managedBy=kubectl" \
  --include-crds=true \
  --output-dir=$HELM_TMPDIR

cat $HELM_TMPDIR/trivy-operator/crds/* $STATIC_DIR/v1_namespace_trivy-system.yaml $HELM_TMPDIR/trivy-operator/templates/* > $STATIC_DIR/trivy-operator.yaml

# Copy all manifests rendered by the Helm chart to the static resources directory,
# where they should be ignored by Git.
# This is done to support local development with partial updates to local cluster.
cp $HELM_TMPDIR/trivy-operator/templates/* $STATIC_DIR/
