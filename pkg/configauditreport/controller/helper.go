package controller

import (
	"context"
	"fmt"

	"github.com/aquasecurity/trivy-operator/pkg/configauditreport"
	"github.com/aquasecurity/trivy-operator/pkg/operator/etc"
	"github.com/aquasecurity/trivy-operator/pkg/policy"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func policies(ctx context.Context, config etc.Config, c client.Client, cac configauditreport.ConfigAuditConfig, log logr.Logger) (*policy.Policies, error) {
	cm := &corev1.ConfigMap{}

	err := c.Get(ctx, client.ObjectKey{
		Namespace: config.Namespace,
		Name:      trivyoperator.PoliciesConfigMapName,
	}, cm)
	if err != nil {
		if !apierrors.IsNotFound(err) {
			return nil, fmt.Errorf("failed getting policies from configmap: %s/%s: %w", config.Namespace, trivyoperator.PoliciesConfigMapName, err)
		}
	}
	return policy.NewPolicies(cm.Data, cac, log), nil
}
