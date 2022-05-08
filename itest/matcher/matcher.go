package matcher

import (
	"fmt"

	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/kube"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	"github.com/onsi/gomega/types"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
)

var (
	trivyScanner = v1alpha1.Scanner{
		Name:    "Trivy",
		Vendor:  "Aqua Security",
		Version: "0.25.2",
	}
	builtInScanner = v1alpha1.Scanner{
		Name:    "Trivy-Operator",
		Vendor:  "Aqua Security",
		Version: "dev",
	}
)

// IsVulnerabilityReportForContainerOwnedBy succeeds if a v1alpha1.VulnerabilityReport has a valid structure,
// corresponds to the given container and is owned by the specified client.Object.
//
// Note: This matcher is not suitable for unit tests because it does not perform a strict validation
// of the actual v1alpha1.VulnerabilityReport.
func IsVulnerabilityReportForContainerOwnedBy(containerName string, owner client.Object) types.GomegaMatcher {
	return &vulnerabilityReportMatcher{
		scheme:        trivyoperator.NewScheme(),
		containerName: containerName,
		owner:         owner,
	}
}

type vulnerabilityReportMatcher struct {
	scheme                *runtime.Scheme
	owner                 client.Object
	containerName         string
	failureMessage        string
	negatedFailureMessage string
}

func (m *vulnerabilityReportMatcher) Match(actual interface{}) (bool, error) {
	_, ok := actual.(v1alpha1.VulnerabilityReport)
	if !ok {
		return false, fmt.Errorf("%T expects a %T", vulnerabilityReportMatcher{}, v1alpha1.VulnerabilityReport{})
	}
	gvk, err := apiutil.GVKForObject(m.owner, m.scheme)
	if err != nil {
		return false, err
	}

	keys, err := m.objectToLabelsAsMatchKeys(m.owner)
	if err != nil {
		return false, err
	}
	keys[trivyoperator.LabelContainerName] = Equal(m.containerName)

	matcher := MatchFields(IgnoreExtras, Fields{
		"ObjectMeta": MatchFields(IgnoreExtras, Fields{
			"Labels": MatchKeys(IgnoreExtras, keys),
			"OwnerReferences": ConsistOf(metav1.OwnerReference{
				APIVersion:         gvk.GroupVersion().Identifier(),
				Kind:               gvk.Kind,
				Name:               m.owner.GetName(),
				UID:                m.owner.GetUID(),
				Controller:         pointer.BoolPtr(true),
				BlockOwnerDeletion: pointer.BoolPtr(false),
			}),
		}),
		"Report": MatchFields(IgnoreExtras, Fields{
			"Scanner":         Equal(trivyScanner),
			"Vulnerabilities": Not(BeNil()),
		}),
	})

	success, err := matcher.Match(actual)
	if err != nil {
		return false, err
	}
	m.failureMessage = matcher.FailureMessage(actual)
	m.negatedFailureMessage = matcher.NegatedFailureMessage(actual)
	return success, nil
}

func (m *vulnerabilityReportMatcher) objectToLabelsAsMatchKeys(obj client.Object) (map[interface{}]types.GomegaMatcher, error) {
	kind := obj.GetObjectKind().GroupVersionKind().Kind
	if kind == "" {
		gvk, err := apiutil.GVKForObject(m.owner, m.scheme)
		if err != nil {
			return nil, err
		}
		kind = gvk.Kind
	}

	labels := kube.ObjectRefToLabels(kube.ObjectRef{
		Kind:      kube.Kind(kind),
		Name:      obj.GetName(),
		Namespace: obj.GetNamespace(),
	})

	keys := make(map[interface{}]types.GomegaMatcher)
	for k, v := range labels {
		keys[k] = Equal(v)
	}
	return keys, nil
}

func (m *vulnerabilityReportMatcher) FailureMessage(_ interface{}) string {
	// TODO Add more descriptive message rather than rely on composed matchers' defaults
	return m.failureMessage
}

func (m *vulnerabilityReportMatcher) NegatedFailureMessage(_ interface{}) string {
	return m.negatedFailureMessage
}

// IsConfigAuditReportOwnedBy succeeds if a v1alpha1.ConfigAuditReport has a valid structure,
// and is owned by the specified client.Object.
//
// Note: This matcher is not suitable for unit tests because it does not perform a strict validation
// of the actual v1alpha1.ConfigAuditReport.
func IsConfigAuditReportOwnedBy(owner client.Object) types.GomegaMatcher {
	return &configAuditReportMatcher{
		owner: owner,
	}
}

type configAuditReportMatcher struct {
	owner                 client.Object
	failureMessage        string
	negatedFailureMessage string
}

func (m *configAuditReportMatcher) Match(actual interface{}) (bool, error) {
	_, ok := actual.(v1alpha1.ConfigAuditReport)
	if !ok {
		return false, fmt.Errorf("%T expects a %T", configAuditReportMatcher{}, v1alpha1.ConfigAuditReport{})
	}
	gvk, err := apiutil.GVKForObject(m.owner, trivyoperator.NewScheme())
	if err != nil {
		return false, err
	}

	matcher := MatchFields(IgnoreExtras, Fields{
		"ObjectMeta": MatchFields(IgnoreExtras, Fields{
			"Labels": MatchKeys(IgnoreExtras, Keys{
				trivyoperator.LabelResourceKind:      Equal(gvk.Kind),
				trivyoperator.LabelResourceName:      Equal(m.owner.GetName()),
				trivyoperator.LabelResourceNamespace: Equal(m.owner.GetNamespace()),
			}),
			"OwnerReferences": ConsistOf(metav1.OwnerReference{
				APIVersion:         gvk.GroupVersion().Identifier(),
				Kind:               gvk.Kind,
				Name:               m.owner.GetName(),
				UID:                m.owner.GetUID(),
				Controller:         pointer.BoolPtr(true),
				BlockOwnerDeletion: pointer.BoolPtr(false),
			}),
		}),
		"Report": MatchFields(IgnoreExtras, Fields{
			"Scanner": Equal(builtInScanner),
		}),
	})
	success, err := matcher.Match(actual)
	if err != nil {
		return false, err
	}
	m.failureMessage = matcher.FailureMessage(actual)
	m.negatedFailureMessage = matcher.NegatedFailureMessage(actual)
	return success, nil
}

func (m *configAuditReportMatcher) FailureMessage(_ interface{}) string {
	// TODO Add more descriptive message rather than rely on composed matchers' defaults
	return m.failureMessage
}

func (m *configAuditReportMatcher) NegatedFailureMessage(_ interface{}) string {
	return m.negatedFailureMessage
}
