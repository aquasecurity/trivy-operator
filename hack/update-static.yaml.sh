#!/usr/bin/env bash

SCRIPT_ROOT=$(dirname "${BASH_SOURCE[0]}")/..

CRD_DIR=$SCRIPT_ROOT/deploy/crd
HELM_DIR=$SCRIPT_ROOT/deploy/helm
STATIC_DIR=$SCRIPT_ROOT/deploy/static

HELM_TMPDIR=$(mktemp -d)
trap "rm -rf $HELM_TMPDIR" EXIT

helm template trivy-operator $HELM_DIR \
  --namespace trivy-system \
  --set="managedBy=kubectl" \
  --output-dir=$HELM_TMPDIR/trivy-operator-helm-template

cp $HELM_TMPDIR/trivy-operator-helm-template/trivy-operator/templates/rbac.yaml $STATIC_DIR/02-trivy-operator.rbac.yaml
cp $HELM_TMPDIR/trivy-operator-helm-template/trivy-operator/templates/config.yaml $STATIC_DIR/03-trivy-operator.config.yaml
cp $HELM_TMPDIR/trivy-operator-helm-template/trivy-operator/templates/policies.yaml $STATIC_DIR/04-trivy-operator.policies.yaml
cp $HELM_TMPDIR/trivy-operator-helm-template/trivy-operator/templates/deployment.yaml $STATIC_DIR/05-trivy-operator.deployment.yaml
cp $HELM_TMPDIR/trivy-operator-helm-template/trivy-operator/templates/service.yaml $STATIC_DIR/06-trivy-operator.service.yaml

cat $CRD_DIR/vulnerabilityreports.crd.yaml \
  $CRD_DIR/configauditreports.crd.yaml \
  $CRD_DIR/exposedsecretreports.crd.yaml \
  $CRD_DIR/clusterconfigauditreports.crd.yaml \
  $STATIC_DIR/01-trivy-operator.ns.yaml \
  $STATIC_DIR/02-trivy-operator.rbac.yaml \
  $STATIC_DIR/03-trivy-operator.config.yaml \
  $STATIC_DIR/04-trivy-operator.policies.yaml \
  $STATIC_DIR/05-trivy-operator.deployment.yaml \
  $STATIC_DIR/06-trivy-operator.service.yaml > $STATIC_DIR/trivy-operator.yaml
