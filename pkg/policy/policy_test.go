package policy_test

import (
	"context"
	"testing"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/policy"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestPolicies_PoliciesByKind(t *testing.T) {

	t.Run("Should return error when kinds are not defined for policy", func(t *testing.T) {
		g := NewGomegaWithT(t)
		config := policy.NewPolicies(map[string]string{
			"library.kubernetes.rego":        "<REGO_A>",
			"library.utils.rego":             "<REGO_B>",
			"policy.access_to_host_pid.rego": "<REGO_C>",
		})
		_, err := config.PoliciesByKind("Pod")
		g.Expect(err).To(MatchError("kinds not defined for policy: policy.access_to_host_pid.rego"))
	})

	t.Run("Should return error when policy is not found", func(t *testing.T) {
		g := NewGomegaWithT(t)
		config := policy.NewPolicies(map[string]string{
			"policy.access_to_host_pid.kinds": "Workload",
		})
		_, err := config.PoliciesByKind("Pod")
		g.Expect(err).To(MatchError("expected policy not found: policy.access_to_host_pid.rego"))
	})

	t.Run("Should return policies as Rego modules", func(t *testing.T) {

		g := NewGomegaWithT(t)
		config := policy.NewPolicies(map[string]string{
			"library.kubernetes.rego":                       "<REGO_A>",
			"library.utils.rego":                            "<REGO_B>",
			"policy.access_to_host_pid.rego":                "<REGO_C>",
			"policy.cpu_not_limited.rego":                   "<REGO_D>",
			"policy.configmap_with_sensitive_data.rego":     "<REGO_E>",
			"policy.configmap_with_secret_data.rego":        "<REGO_F>",
			"policy.object_without_recommended_labels.rego": "<REGO_G>",

			"policy.access_to_host_pid.kinds":                "Pod,ReplicaSet",
			"policy.cpu_not_limited.kinds":                   "Workload",
			"policy.configmap_with_sensitive_data.kinds":     "ConfigMap",
			"policy.configmap_with_secret_data.kinds":        "ConfigMap",
			"policy.object_without_recommended_labels.kinds": "*",

			// This one should be skipped (no .rego suffix)
			"policy.privileged": "<REGO_E>",
			// This one should be skipped (no policy. prefix)
			"foo": "bar",
		})
		g.Expect(config.PoliciesByKind("Pod")).To(Equal(map[string]string{
			"policy.access_to_host_pid.rego":                "<REGO_C>",
			"policy.cpu_not_limited.rego":                   "<REGO_D>",
			"policy.object_without_recommended_labels.rego": "<REGO_G>",
		}))
		g.Expect(config.PoliciesByKind("ConfigMap")).To(Equal(map[string]string{
			"policy.configmap_with_sensitive_data.rego":     "<REGO_E>",
			"policy.configmap_with_secret_data.rego":        "<REGO_F>",
			"policy.object_without_recommended_labels.rego": "<REGO_G>",
		}))
	})
}

func TestPolicies_Applicable(t *testing.T) {

	testCases := []struct {
		name     string
		data     map[string]string
		resource client.Object
		expected bool
	}{
		{
			name: "Should return false if there are no policies",
			data: map[string]string{},
			resource: &corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Pod",
					APIVersion: "v1",
				},
			},
			expected: false,
		},
		{
			name: "Should return true if there is at least one policy",
			data: map[string]string{
				"policy.kubernetes.kinds": "Pod",
				"policy.kubernetes.rego": `package main

deny[res] {
  input.kind == "Deployment"
  not input.spec.template.spec.securityContext.runAsNonRoot

  msg := "Containers must not run as root"

  res := {
    "msg": msg,
    "title": "Runs as root user"
  }
}
`},
			resource: &corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Pod",
					APIVersion: "v1",
				},
			},
			expected: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewGomegaWithT(t)
			ready, _, err := policy.NewPolicies(tc.data).Applicable(tc.resource)
			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(ready).To(Equal(tc.expected))
		})
	}

}

func TestPolicies_Eval(t *testing.T) {
	testCases := []struct {
		name          string
		resource      client.Object
		policies      map[string]string
		results       policy.Results
		expectedError string
	}{
		{
			name: "Should eval deny rule with invalid resource as failed check",
			resource: &appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Deployment",
					APIVersion: "appsv1",
				},
				Spec: appsv1.DeploymentSpec{
					Template: corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{
									Name:  "nginx",
									Image: "nginx:1.16",
								},
							},
						},
					},
				},
			},
			policies: map[string]string{
				"library.utils.rego": `package lib.utils

has_key(x, k) {
  _ = x[k]
}`,
				"policy.policy1.kinds": "Workload",
				"policy.policy1.rego": `package appshield.kubernetes.KSV014

__rego_metadata__ := {
	"id": "KSV014",
	"title": "Root file system is not read-only",
	"description": "An immutable root file system prevents applications from writing to their local disk",
	"severity": "LOW",
	"type": "Kubernetes Security Check"
}

deny[res] {
	input.kind == "Deployment"
	not input.spec.template.spec.securityContext.runAsNonRoot

	msg := "Containers must not run as root"

	res := {
		"id": __rego_metadata__.id,
		"title": __rego_metadata__.title,
		"severity": __rego_metadata__.severity,
		"type": __rego_metadata__.type,
		"msg": msg
	}
}
`,
			},
			results: []policy.Result{
				{
					Success: false,
					Metadata: policy.Metadata{
						ID:          "KSV014",
						Title:       "Root file system is not read-only",
						Description: "An immutable root file system prevents applications from writing to their local disk",
						Severity:    v1alpha1.SeverityLow,
						Type:        "Kubernetes Security Check",
					},
					Messages: []string{"Containers must not run as root"},
				},
			},
		},
		{
			name: "Should eval deny rule with valid resource as successful check",
			resource: &appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Deployment",
					APIVersion: "appsv1",
				},
				Spec: appsv1.DeploymentSpec{
					Template: corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							SecurityContext: &corev1.PodSecurityContext{
								RunAsNonRoot: pointer.BoolPtr(true),
							},
							Containers: []corev1.Container{
								{
									Name:  "nginx",
									Image: "nginx:1.16",
								},
							},
						},
					},
				},
			},
			policies: map[string]string{
				"library.utils.rego": `package lib.utils

has_key(x, k) {
  _ = x[k]
}`,
				"policy.policy1.kinds": "Workload",
				"policy.policy1.rego": `package appshield.kubernetes.KSV014

__rego_metadata__ := {
	"id": "KSV014",
	"title": "Root file system is not read-only",
	"description": "An immutable root file system prevents applications from writing to their local disk",
	"severity": "LOW",
	"type": "Kubernetes Security Check"
}

deny[res] {
	input.kind == "Deployment"
	not input.spec.template.spec.securityContext.runAsNonRoot

	msg := "Containers must not run as root"

	res := {
		"id": __rego_metadata__.id,
		"title": __rego_metadata__.title,
		"severity": __rego_metadata__.severity,
		"type": __rego_metadata__.type,
		"msg": msg
	}
}
`,
			},
			results: []policy.Result{
				{
					Success: true,
					Metadata: policy.Metadata{
						ID:          "KSV014",
						Severity:    v1alpha1.SeverityLow,
						Title:       "Root file system is not read-only",
						Description: "An immutable root file system prevents applications from writing to their local disk",
						Type:        "Kubernetes Security Check",
					},
				},
			},
		},
		{
			name: "Should eval warn rule with invalid resource as failed check",
			resource: &appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Deployment",
					APIVersion: "appsv1",
				},
				Spec: appsv1.DeploymentSpec{
					Template: corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{
									Name:  "nginx",
									Image: "nginx:1.16",
								},
							},
						},
					},
				},
			},
			policies: map[string]string{
				"library.utils.rego": `package lib.utils

has_key(x, k) {
  _ = x[k]
}`,
				"policy.policy1.kinds": "Workload",
				"policy.policy1.rego": `package appshield.kubernetes.KSV014

__rego_metadata__ := {
	"id": "KSV014",
	"title": "Root file system is not read-only",
	"description": "An immutable root file system prevents applications from writing to their local disk",
	"severity": "MEDIUM",
	"type": "Kubernetes Security Check"
}

warn[res] {
	input.kind == "Deployment"
	not input.spec.template.spec.securityContext.runAsNonRoot

	msg := "Containers must not run as root"

	res := {
		"id": __rego_metadata__.id,
		"title": __rego_metadata__.title,
		"severity": __rego_metadata__.severity,
		"type": __rego_metadata__.type,
		"msg": msg
	}
}
`,
			},
			results: []policy.Result{
				{
					Success: false,
					Metadata: policy.Metadata{
						ID:          "KSV014",
						Title:       "Root file system is not read-only",
						Description: "An immutable root file system prevents applications from writing to their local disk",
						Severity:    v1alpha1.SeverityMedium,
						Type:        "Kubernetes Security Check",
					},
					Messages: []string{"Containers must not run as root"},
				},
			},
		},
		{
			name: "Should eval warn rule with valid resource as successful check",
			resource: &appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Deployment",
					APIVersion: "appsv1",
				},
				Spec: appsv1.DeploymentSpec{
					Template: corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							SecurityContext: &corev1.PodSecurityContext{
								RunAsNonRoot: pointer.BoolPtr(true),
							},
							Containers: []corev1.Container{
								{
									Name:  "nginx",
									Image: "nginx:1.16",
								},
							},
						},
					},
				},
			},
			policies: map[string]string{
				"library.utils.rego": `package lib.utils

has_key(x, k) {
  _ = x[k]
}`,
				"policy.policy1.kinds": "Workload",
				"policy.policy1.rego": `package appshield.kubernetes.KSV014

__rego_metadata__ := {
	"id": "KSV014",
	"title": "Root file system is not read-only",
	"description": "An immutable root file system prevents applications from writing to their local disk",
	"severity": "LOW",
	"type": "Kubernetes Security Check"
}

warn[res] {
	input.kind == "Deployment"
	not input.spec.template.spec.securityContext.runAsNonRoot

	msg := "Containers must not run as root"

	res := {
		"id": __rego_metadata__.id,
		"title": __rego_metadata__.title,
		"severity": __rego_metadata__.severity,
		"type": __rego_metadata__.type,
		"msg": msg
	}
}
`,
			},
			results: []policy.Result{
				{
					Success: true,
					Metadata: policy.Metadata{
						ID:          "KSV014",
						Severity:    v1alpha1.SeverityLow,
						Title:       "Root file system is not read-only",
						Description: "An immutable root file system prevents applications from writing to their local disk",
						Type:        "Kubernetes Security Check",
					},
				},
			},
		},
		{
			name:          "Should return error when resource is nil",
			resource:      nil,
			expectedError: "resource must not be nil",
		},
		{
			name:          "Should return error when resource kind is blank",
			resource:      &appsv1.Deployment{},
			policies:      map[string]string{},
			expectedError: "resource kind must not be blank",
		},
		{
			name: "Should return error when policy cannot be parsed",
			resource: &appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Deployment",
					APIVersion: "appsv1",
				},
			},
			policies: map[string]string{
				"policy.invalid.kinds": "Workload",
				"policy.invalid.rego":  "$^&!",
			},
			expectedError: "failed parsing Rego policy: policy.invalid.rego: 1 error occurred: policy.invalid.rego:1: rego_parse_error: illegal token\n\t$^&!\n\t^",
		},
		{
			name: "Should return error when library cannot be parsed",
			resource: &appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Deployment",
					APIVersion: "appsv1",
				},
				Spec: appsv1.DeploymentSpec{
					Template: corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							SecurityContext: &corev1.PodSecurityContext{
								RunAsNonRoot: pointer.BoolPtr(true),
							},
							Containers: []corev1.Container{
								{
									Name:  "nginx",
									Image: "nginx:1.16",
								},
							},
						},
					},
				},
			},
			policies: map[string]string{
				"library.utils.rego":   "$^&!",
				"policy.policy1.kinds": "Workload",
				"policy.policy1.rego": `package appshield.kubernetes.KSV014

__rego_metadata__ := {
	"id": "KSV014",
	"title": "Root file system is not read-only",
	"description": "An immutable root file system prevents applications from writing to their local disk",
	"severity": "LOW",
	"type": "Kubernetes Security Check"
}

warn[res] {
	input.kind == "Deployment"
	not input.spec.template.spec.securityContext.runAsNonRoot

	msg := "Containers must not run as root"

	res := {
		"id": __rego_metadata__.id,
		"title": __rego_metadata__.title,
		"severity": __rego_metadata__.severity,
		"type": __rego_metadata__.type,
		"msg": msg
	}
}
`,
			},
			expectedError: "failed parsing Rego library: library.utils.rego: 1 error occurred: library.utils.rego:1: rego_parse_error: illegal token\n\t$^&!\n\t^",
		},
		{
			name: "Should return error when __rego_metadata__ is not defined",
			resource: &appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Deployment",
					APIVersion: "appsv1",
				},
				Spec: appsv1.DeploymentSpec{
					Template: corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							SecurityContext: &corev1.PodSecurityContext{
								RunAsNonRoot: pointer.BoolPtr(true),
							},
							Containers: []corev1.Container{
								{
									Name:  "nginx",
									Image: "nginx:1.16",
								},
							},
						},
					},
				},
			},
			policies: map[string]string{
				"policy.policy1.kinds": "Workload",
				"policy.policy1.rego": `package appshield.kubernetes.KSV014

warn[res] {
	input.kind == "Deployment"
	not input.spec.template.spec.securityContext.runAsNonRoot

	msg := "Containers must not run as root"

	res := {
		"id": "KSV014",
		"title": "Root file system is not read-only",
		"severity": "LOW",
		"type": "Kubernetes Security Check",
		"msg": msg
	}
}
`,
			},
			expectedError: "failed parsing policy metadata: policy.policy1.rego",
		},
		{
			name: "Should return error when __rego_metadata__ cannot be parsed",
			resource: &appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Deployment",
					APIVersion: "appsv1",
				},
				Spec: appsv1.DeploymentSpec{
					Template: corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{
									Name:  "nginx",
									Image: "nginx:1.16",
								},
							},
						},
					},
				},
			},
			policies: map[string]string{
				"policy.policy1.kinds": "Workload",
				"policy.policy1.rego": `package appshield.kubernetes.KSV014

__rego_metadata__ := {
	"id": "KSV014",
	"title": "Root file system is not read-only",
	"description": "An immutable root file system prevents applications from writing to their local disk",
	"severity": "SEVERE",
	"type": "Kubernetes Security Check"
}

deny[res] {
	input.kind == "Deployment"
	not input.spec.template.spec.securityContext.runAsNonRoot

	msg := "Containers must not run as root"

	res := {
		"id": __rego_metadata__.id,
		"title": __rego_metadata__.title,
		"severity": __rego_metadata__.severity,
		"type": __rego_metadata__.type,
		"msg": msg
	}
}
`,
			},
			expectedError: "failed parsing policy metadata: policy.policy1.rego: failed parsing severity: unrecognized name literal: SEVERE",
		},
		{
			name: "Should eval deny rule with any resource and multiple messages",
			resource: &appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Deployment",
					APIVersion: "appsv1",
				},
				Spec: appsv1.DeploymentSpec{
					Template: corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{
									Name:  "nginx",
									Image: "nginx:1.16",
								},
							},
						},
					},
				},
			},
			policies: map[string]string{
				"policy.uses_image_tag_latest.kinds": "Workload",
				"policy.uses_image_tag_latest.rego": `package test

__rego_metadata__ := {
	"id": "KSV013",
	"avd_id": "AVD-KSV-0013",
	"title": "Image tag ':latest' used",
	"short_code": "use-specific-tags",
	"version": "v1.0.0",
	"severity": "LOW",
	"type": "Kubernetes Security Check",
	"description": "It is best to avoid using the ':latest' image tag when deploying containers in production. Doing so makes it hard to track which version of the image is running, and hard to roll back the version.",
	"recommended_actions": "Use a specific container image tag that is not 'latest'.",
	"url": "https://kubernetes.io/docs/concepts/configuration/overview/#container-images",
}

messages = [ "msg1", "msg2" ]

deny[res] {

	msg := messages[_]

	res := {
		"msg": msg,
		"id": __rego_metadata__.id,
		"title": __rego_metadata__.title,
		"severity": __rego_metadata__.severity,
		"type": __rego_metadata__.type,
	}
}`,
			},
			results: []policy.Result{
				{
					Metadata: policy.Metadata{
						ID:          "KSV013",
						Title:       "Image tag ':latest' used",
						Description: "It is best to avoid using the ':latest' image tag when deploying containers in production. Doing so makes it hard to track which version of the image is running, and hard to roll back the version.",
						Severity:    "LOW",
						Type:        "Kubernetes Security Check",
					},
					Messages: []string{"msg1", "msg2"},
					Success:  false,
				},
			},
		},
		{
			name: "Should eval warn rule with any resource and multiple messages",
			resource: &appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Deployment",
					APIVersion: "appsv1",
				},
				Spec: appsv1.DeploymentSpec{
					Template: corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{
									Name:  "nginx",
									Image: "nginx:1.16",
								},
							},
						},
					},
				},
			},
			policies: map[string]string{
				"policy.uses_image_tag_latest.kinds": "Workload",
				"policy.uses_image_tag_latest.rego": `package test

__rego_metadata__ := {
	"id": "KSV013",
	"avd_id": "AVD-KSV-0013",
	"title": "Image tag ':latest' used",
	"short_code": "use-specific-tags",
	"version": "v1.0.0",
	"severity": "LOW",
	"type": "Kubernetes Security Check",
	"description": "It is best to avoid using the ':latest' image tag when deploying containers in production. Doing so makes it hard to track which version of the image is running, and hard to roll back the version.",
	"recommended_actions": "Use a specific container image tag that is not 'latest'.",
	"url": "https://kubernetes.io/docs/concepts/configuration/overview/#container-images",
}

messages = [ "msg1", "msg2" ]

deny[res] {

	msg := messages[_]

	res := {
		"msg": msg,
		"id": __rego_metadata__.id,
		"title": __rego_metadata__.title,
		"severity": __rego_metadata__.severity,
		"type": __rego_metadata__.type,
	}
}`,
			},
			results: []policy.Result{
				{
					Metadata: policy.Metadata{
						ID:          "KSV013",
						Title:       "Image tag ':latest' used",
						Description: "It is best to avoid using the ':latest' image tag when deploying containers in production. Doing so makes it hard to track which version of the image is running, and hard to roll back the version.",
						Severity:    "LOW",
						Type:        "Kubernetes Security Check",
					},
					Messages: []string{"msg1", "msg2"},
					Success:  false,
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewGomegaWithT(t)
			checks, err := policy.NewPolicies(tc.policies).Eval(context.TODO(), tc.resource)
			if tc.expectedError != "" {
				g.Expect(err).To(MatchError(tc.expectedError))
			} else {
				g.Expect(err).ToNot(HaveOccurred())
				g.Expect(checks).To(Equal(tc.results))
			}
		})
	}
}

func TestNewMetadata(t *testing.T) {
	testCases := []struct {
		name             string
		values           map[string]interface{}
		expectedMetadata policy.Metadata
		expectedError    string
	}{
		{
			name:          "Should return error when value is nil",
			values:        nil,
			expectedError: "values must not be nil",
		},
		{
			name: "Should return error when severity key is not set",
			values: map[string]interface{}{
				"id":          "some id",
				"title":       "some title",
				"type":        "some type",
				"description": "some description",
			},
			expectedError: "required key not found: severity",
		},
		{
			name: "Should return error when severity value is nil",
			values: map[string]interface{}{
				"severity":    nil,
				"id":          "some id",
				"title":       "some title",
				"type":        "some type",
				"description": "some description",
			},
			expectedError: "required value is nil for key: severity",
		},
		{
			name: "Should return error when severity value is blank",
			values: map[string]interface{}{
				"severity":    "",
				"id":          "some id",
				"title":       "some title",
				"type":        "some type",
				"description": "some description",
			},
			expectedError: "required value is blank for key: severity",
		},
		{
			name: "Should return error when severity value is invalid",
			values: map[string]interface{}{
				"severity":    "INVALID",
				"id":          "some id",
				"title":       "some title",
				"type":        "some type",
				"description": "some description",
			},
			expectedError: "failed parsing severity: unrecognized name literal: INVALID",
		},
		{
			name: "Should return error when id key is not set",
			values: map[string]interface{}{
				"severity":    "CRITICAL",
				"title":       "some title",
				"type":        "some type",
				"description": "some description",
			},
			expectedError: "required key not found: id",
		},
		{
			name: "Should return error when id value is nil",
			values: map[string]interface{}{
				"severity":    "CRITICAL",
				"id":          nil,
				"title":       "some title",
				"type":        "some type",
				"description": "some description",
			},
			expectedError: "required value is nil for key: id",
		},
		{
			name: "Should return error when id value is blank",
			values: map[string]interface{}{
				"severity":    "CRITICAL",
				"id":          "",
				"title":       "some title",
				"type":        "some type",
				"description": "some description",
			},
			expectedError: "required value is blank for key: id",
		},
		{
			name: "Should return error when id value is not string",
			values: map[string]interface{}{
				"severity":    "CRITICAL",
				"id":          3,
				"title":       "some title",
				"type":        "some type",
				"description": "some description",
			},
			expectedError: "expected string got int for key: id",
		},
		{
			name: "Should return error when title key is not set",
			values: map[string]interface{}{
				"severity":    "CRITICAL",
				"id":          "some id",
				"type":        "some type",
				"description": "some description",
			},
			expectedError: "required key not found: title",
		},
		{
			name: "Should return error when title value is nil",
			values: map[string]interface{}{
				"severity": "CRITICAL",
				"id":       "KVH012",
				"title":    nil,
			},
			expectedError: "required value is nil for key: title",
		},
		{
			name: "Should return error when title value is blank",
			values: map[string]interface{}{
				"severity":    "CRITICAL",
				"id":          "some id",
				"title":       "",
				"type":        "some type",
				"description": "some description",
			},
			expectedError: "required value is blank for key: title",
		},
		{
			name: "Should return error when type key is not set",
			values: map[string]interface{}{
				"severity":    "CRITICAL",
				"id":          "some id",
				"title":       "some title",
				"description": "some description",
			},
			expectedError: "required key not found: type",
		},
		{
			name: "Should return error when type value is nil",
			values: map[string]interface{}{
				"severity":    "CRITICAL",
				"id":          "some id",
				"title":       "some title",
				"type":        nil,
				"description": "some description",
			},
			expectedError: "required value is nil for key: type",
		},
		{
			name: "Should return error when type value is blank",
			values: map[string]interface{}{
				"severity":    "CRITICAL",
				"id":          "some id",
				"title":       "some title",
				"type":        "",
				"description": "some description",
			},
			expectedError: "required value is blank for key: type",
		},
		{
			name: "Should return error when description key is not set",
			values: map[string]interface{}{
				"severity": "CRITICAL",
				"id":       "some id",
				"title":    "some title",
				"type":     "some type",
			},
			expectedError: "required key not found: description",
		},
		{
			name: "Should return metadata",
			values: map[string]interface{}{
				"severity":    "CRITICAL",
				"id":          "some id",
				"title":       "some title",
				"type":        "some type",
				"description": "some description",
			},
			expectedMetadata: policy.Metadata{
				ID:          "some id",
				Title:       "some title",
				Severity:    "CRITICAL",
				Type:        "some type",
				Description: "some description",
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewGomegaWithT(t)
			metadata, err := policy.NewMetadata(tc.values)
			if tc.expectedError != "" {
				g.Expect(err).To(MatchError(tc.expectedError))
			} else {
				g.Expect(err).ToNot(HaveOccurred())
				g.Expect(metadata).To(Equal(tc.expectedMetadata))
			}
		})
	}

}

func TestNewMessage(t *testing.T) {
	testCases := []struct {
		name           string
		values         map[string]interface{}
		expectedResult string
		expectedError  string
	}{
		{
			name:          "Should return error when values is nil",
			values:        nil,
			expectedError: "values must not be nil",
		},
		{
			name:          "Should return error when msg key is not set",
			values:        map[string]interface{}{},
			expectedError: "required key not found: msg",
		},
		{
			name: "Should return error when msg value is nil",
			values: map[string]interface{}{
				"msg": nil,
			},
			expectedError: "required value is nil for key: msg",
		},
		{
			name: "Should return error when msg value is blank",
			values: map[string]interface{}{
				"msg": "",
			},
			expectedError: "required value is blank for key: msg",
		},
		{
			name: "Should return result",
			values: map[string]interface{}{
				"msg": "some message",
			},
			expectedResult: "some message",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewGomegaWithT(t)
			result, err := policy.NewMessage(tc.values)
			if tc.expectedError != "" {
				g.Expect(err).To(MatchError(tc.expectedError))
			} else {
				g.Expect(err).ToNot(HaveOccurred())
				g.Expect(result).To(Equal(tc.expectedResult))
			}
		})
	}
}
