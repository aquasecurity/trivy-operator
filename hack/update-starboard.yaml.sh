#!/usr/bin/env bash

SCRIPT_ROOT=$(dirname "${BASH_SOURCE[0]}")/..

CRD_DIR=$SCRIPT_ROOT/deploy/crd
STATIC_DIR=$SCRIPT_ROOT/deploy/static

cat $CRD_DIR/vulnerabilityreports.crd.yaml \
  $CRD_DIR/configauditreports.crd.yaml \
  $CRD_DIR/clusterconfigauditreports.crd.yaml \
  $CRD_DIR/ciskubebenchreports.crd.yaml \
  $CRD_DIR/clustercompliancereports.crd.yaml \
  $CRD_DIR/clustercompliancedetailreports.crd.yaml \
  $STATIC_DIR/01-trivy-operator.ns.yaml \
  $STATIC_DIR/02-trivy-operator.rbac.yaml \
  $STATIC_DIR/03-trivy-operator.config.yaml \
  $STATIC_DIR/04-trivy-operator.policies.yaml \
  $STATIC_DIR/05-trivy-operator.deployment.yaml > $STATIC_DIR/trivy-operator.yaml
