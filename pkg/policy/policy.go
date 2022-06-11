package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/scanners/kubernetes"
	"github.com/aquasecurity/defsec/pkg/scanners/options"

	"github.com/aquasecurity/trivy-operator/pkg/kube"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	keyPrefixPolicy  = "policy."
	keyPrefixLibrary = "library."
	keySuffixKinds   = ".kinds"
	keySuffixRego    = ".rego"
)

const (
	kindAny      = "*"
	kindWorkload = "Workload"
)

type Policies struct {
	data map[string]string
}

func NewPolicies(data map[string]string) *Policies {
	return &Policies{
		data: data,
	}
}

func (p *Policies) Libraries() map[string]string {
	libs := make(map[string]string)
	for key, value := range p.data {
		if !strings.HasPrefix(key, keyPrefixLibrary) {
			continue
		}
		if !strings.HasSuffix(key, keySuffixRego) {
			continue
		}
		libs[key] = value
	}
	return libs
}

func (p *Policies) PoliciesByKind(kind string) (map[string]string, error) {
	policies := make(map[string]string)
	for key, value := range p.data {
		if strings.HasSuffix(key, keySuffixRego) && strings.HasPrefix(key, keyPrefixPolicy) {
			// Check if kinds were defined for this policy
			kindsKey := strings.TrimSuffix(key, keySuffixRego) + keySuffixKinds
			if _, ok := p.data[kindsKey]; !ok {
				return nil, fmt.Errorf("kinds not defined for policy: %s", key)
			}
		}

		if !strings.HasSuffix(key, keySuffixKinds) {
			continue
		}
		for _, k := range strings.Split(value, ",") {
			if k == kindWorkload && !kube.IsWorkload(kind) {
				continue
			}
			if k != kindAny && k != kindWorkload && k != kind {
				continue
			}

			policyKey := strings.TrimSuffix(key, keySuffixKinds) + keySuffixRego
			var ok bool

			policies[policyKey], ok = p.data[policyKey]
			if !ok {
				return nil, fmt.Errorf("expected policy not found: %s", policyKey)
			}
		}
	}
	return policies, nil
}

func (p *Policies) Hash(kind string) (string, error) {
	modules, err := p.ModulesByKind(kind)
	if err != nil {
		return "", err
	}
	return kube.ComputeHash(modules), nil
}

func (p *Policies) ModulesByKind(kind string) (map[string]string, error) {
	modules, err := p.PoliciesByKind(kind)
	if err != nil {
		return nil, err
	}
	for key, value := range p.Libraries() {
		modules[key] = value
	}
	return modules, nil
}
func (p *Policies) ModulesReaderByKind(kind string) ([]io.Reader, error) {
	modByKind, err := p.ModulesByKind(kind)
	if err != nil {
		return nil, err
	}
	policyReader := make([]io.Reader, 0)
	for _, mod := range modByKind {
		policyReader = append(policyReader, io.NopCloser(strings.NewReader(mod)))
	}
	return policyReader, nil
}

func (p *Policies) Applicable(resource client.Object) (bool, string, error) {
	resourceKind := resource.GetObjectKind().GroupVersionKind().Kind
	if resourceKind == "" {
		return false, "", errors.New("resource kind must not be blank")
	}
	policies, err := p.PoliciesByKind(resourceKind)
	if err != nil {
		return false, "", err
	}
	if len(policies) == 0 {
		return false, fmt.Sprintf("no policies found for kind %s", resource.GetObjectKind().GroupVersionKind().Kind), nil
	}
	return true, "", nil
}

// Eval evaluates Rego policies with Kubernetes resource client.Object as input.
//
// TODO(danielpacak) Compile and cache prepared queries to make Eval more efficient.
//                   We can reuse prepared queries so long policies do not change.
func (p *Policies) Eval(ctx context.Context, resource client.Object) (scan.Results, error) {
	if resource == nil {
		return nil, fmt.Errorf("resource must not be nil")
	}
	resourceKind := resource.GetObjectKind().GroupVersionKind().Kind
	if resourceKind == "" {
		return nil, fmt.Errorf("resource kind must not be blank")
	}

	policiesReader, err := p.ModulesReaderByKind(resourceKind)
	if err != nil {
		return nil, fmt.Errorf("failed listing policies by kind: %s: %w", resourceKind, err)
	}
	// making sure handles for reader not remain open in case of failure with lib scanner
	defer CloseReaders(policiesReader)
	scanner := kubernetes.NewScanner(options.ScannerWithEmbeddedPolicies(false), options.OptionWithPolicyReaders(policiesReader...))
	b, err := json.Marshal(resource)
	if err != nil {
		return nil, err
	}
	scanResult, err := scanner.ScanReader(ctx, "./input.json", strings.NewReader(string(b)))
	if err != nil {
		return nil, err
	}
	//special case when lib return nil for both checks and error
	if scanResult == nil && err == nil {
		return nil, fmt.Errorf("failed to run policy checks on resources")
	}
	return scanResult, nil
}

func CloseReaders(readers []io.Reader) error {
	if len(readers) == 0 {
		return nil
	}
	for _, r := range readers {
		cr := r.(io.ReadCloser)
		err := cr.Close()
		if err != nil {
			return err
		}
	}
	return nil
}
