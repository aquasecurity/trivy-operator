package configauditreport

import (
	"context"
	"fmt"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/kube"
	"github.com/aquasecurity/trivy-operator/pkg/policy"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Scanner struct {
	buildInfo      trivyoperator.BuildInfo
	scheme         *runtime.Scheme
	client         client.Client
	objectResolver *kube.ObjectResolver
}

func NewScanner(buildInfo trivyoperator.BuildInfo, client client.Client) *Scanner {
	return &Scanner{
		buildInfo: buildInfo,
		scheme:    client.Scheme(),
		client:    client,
		objectResolver: &kube.ObjectResolver{
			Client: client,
		},
	}
}

func (s *Scanner) Scan(ctx context.Context, resourceRef kube.ObjectRef) (*ReportBuilder, error) {
	resource, err := s.objectResolver.ObjectFromObjectRef(ctx, resourceRef)
	if err != nil {
		return nil, fmt.Errorf("failed resolving resource from ref: %w", err)
	}

	resource, err = s.objectResolver.ReportOwner(ctx, resource)
	if err != nil {
		return nil, fmt.Errorf("failed resolving report owner: %w", err)
	}

	resourceKind := resource.GetObjectKind().GroupVersionKind().Kind

	policies, err := s.policies(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed getting policies: %w", err)
	}

	applicable, reason, err := policies.Applicable(resource)
	if err != nil {
		return nil, err
	}
	if !applicable {
		return nil, fmt.Errorf("not applicable: %s", reason)
	}

	results, err := policies.Eval(ctx, resource)
	if err != nil {
		return nil, fmt.Errorf("failed evaluating policies: %w", err)
	}

	checks := make([]v1alpha1.Check, len(results))
	for i, result := range results {
		checks[i] = v1alpha1.Check{
			ID:          result.Metadata.ID,
			Title:       result.Metadata.Title,
			Description: result.Metadata.Description,
			Severity:    result.Metadata.Severity,
			Category:    result.Metadata.Type,

			Success:  result.Success,
			Messages: result.Messages,
		}
	}

	data := v1alpha1.ConfigAuditReportData{
		Scanner: v1alpha1.Scanner{
			Name:    "Trivy-Operator",
			Vendor:  "Aqua Security",
			Version: s.buildInfo.Version,
		},
		Summary: v1alpha1.ConfigAuditSummaryFromChecks(checks),
		Checks:  checks,

		PodChecks:       checks,
		ContainerChecks: map[string][]v1alpha1.Check{},
	}

	resourceHash, err := kube.ComputeSpecHash(resource)
	if err != nil {
		return nil, fmt.Errorf("failed computing spec hash: %w", err)
	}
	scannerConfigHash, err := policies.Hash(resourceKind)
	if err != nil {
		return nil, fmt.Errorf("failed computing scanner config hash: %w", err)
	}

	return NewReportBuilder(s.scheme).
		Controller(resource).
		ResourceSpecHash(resourceHash).
		PluginConfigHash(scannerConfigHash).
		Data(data), nil
}

func (s *Scanner) policies(ctx context.Context) (*policy.Policies, error) {
	cm := &corev1.ConfigMap{}

	err := s.client.Get(ctx, client.ObjectKey{
		Namespace: trivyoperator.NamespaceName,
		Name:      trivyoperator.PoliciesConfigMapName,
	}, cm)
	if err != nil {
		return nil, fmt.Errorf("failed getting policies from configmap: %s/%s: %w", trivyoperator.NamespaceName, trivyoperator.PoliciesConfigMapName, err)
	}
	return policy.NewPolicies(cm.Data), nil
}
