package policy

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/kube"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
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

const (
	// varMessage is the name of Rego variable used to bind deny or warn
	// messages.
	varMessage = "msg"
	// varMetadata is the name of Rego variable used to bind policy metadata.
	varMetadata = "md"
	// varResult is the name of Rego variable used to bind result of evaluating
	// deny or warn rules.
	varResult = "res"
)

// Metadata describes policy metadata.
type Metadata struct {
	ID          string
	Title       string
	Severity    v1alpha1.Severity
	Type        string
	Description string
}

// NewMetadata constructs new Metadata based on raw values.
func NewMetadata(values map[string]interface{}) (Metadata, error) {
	if values == nil {
		return Metadata{}, errors.New("values must not be nil")
	}
	severityString, err := requiredStringValue(values, "severity")
	if err != nil {
		return Metadata{}, err
	}
	severity, err := v1alpha1.StringToSeverity(severityString)
	if err != nil {
		return Metadata{}, fmt.Errorf("failed parsing severity: %w", err)
	}
	id, err := requiredStringValue(values, "id")
	if err != nil {
		return Metadata{}, err
	}
	title, err := requiredStringValue(values, "title")
	if err != nil {
		return Metadata{}, err
	}
	policyType, err := requiredStringValue(values, "type")
	if err != nil {
		return Metadata{}, err
	}
	description, err := requiredStringValue(values, "description")
	if err != nil {
		return Metadata{}, err
	}

	return Metadata{
		Severity:    severity,
		ID:          id,
		Title:       title,
		Type:        policyType,
		Description: description,
	}, nil
}

// Result describes result of evaluating a Rego policy that defines `deny` or
// `warn` rules.
type Result struct {
	// Metadata describes Rego policy metadata.
	Metadata Metadata

	// Success represents the status of evaluating Rego policy.
	Success bool

	// Messages deny or warning messages.
	Messages []string
}

type Results []Result

// NewMessage constructs new message string based on raw values.
func NewMessage(values map[string]interface{}) (string, error) {
	if values == nil {
		return "", errors.New("values must not be nil")
	}
	message, err := requiredStringValue(values, varMessage)
	if err != nil {
		return "", err
	}
	return message, nil
}

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
func (p *Policies) Eval(ctx context.Context, resource client.Object) (Results, error) {
	if resource == nil {
		return nil, fmt.Errorf("resource must not be nil")
	}
	resourceKind := resource.GetObjectKind().GroupVersionKind().Kind
	if resourceKind == "" {
		return nil, fmt.Errorf("resource kind must not be blank")
	}

	var results Results

	policies, err := p.PoliciesByKind(resourceKind)
	if err != nil {
		return nil, fmt.Errorf("failed listing policies by kind: %s: %w", resourceKind, err)
	}

	for policyName, policyCode := range policies {
		parsedModules := make(map[string]*ast.Module)

		for libraryName, libraryCode := range p.Libraries() {
			var parsedLibrary *ast.Module
			parsedLibrary, err = ast.ParseModule(libraryName, libraryCode)
			if err != nil {
				return nil, fmt.Errorf("failed parsing Rego library: %s: %w", libraryName, err)
			}
			parsedModules[libraryName] = parsedLibrary
		}

		parsedPolicy, err := ast.ParseModule(policyName, policyCode)
		if err != nil {
			return nil, fmt.Errorf("failed parsing Rego policy: %s: %w", policyName, err)
		}
		parsedModules[policyName] = parsedPolicy

		compiler := ast.NewCompiler()
		compiler.Compile(parsedModules)
		if compiler.Failed() {
			return nil, fmt.Errorf("failed compiling Rego policy: %s: %w", policyName, compiler.Errors)
		}

		metadataQuery := fmt.Sprintf("md = %s.__rego_metadata__", parsedPolicy.Package.Path.String())
		metadata, err := rego.New(
			rego.Compiler(compiler),
			rego.Query(metadataQuery),
		).Eval(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed evaluating Rego metadata rule: %s: %w", metadataQuery, err)
		}

		metadataResult, hasMetadataResult := hasBinding(metadata, varMetadata)

		if !hasMetadataResult {
			return nil, fmt.Errorf("failed parsing policy metadata: %s", policyName)
		}

		md, err := NewMetadata(metadataResult)
		if err != nil {
			return nil, fmt.Errorf("failed parsing policy metadata: %s: %w", policyName, err)
		}

		denyQuery := fmt.Sprintf("%s.deny[res]", parsedPolicy.Package.Path.String())
		deny, err := rego.New(
			rego.Compiler(compiler),
			rego.Query(denyQuery),
			rego.Input(resource),
		).Eval(ctx)

		if err != nil {
			return nil, fmt.Errorf("failed evaluating Rego deny rule: %s: %w", denyQuery, err)
		}

		denyValues, hasDenyValues := hasBindings(deny, varResult)
		if hasDenyValues {
			denyResults, err := valuesToResults(md, denyValues)
			if err != nil {
				return nil, fmt.Errorf("failed parsing deny rule result: %s: %w", denyQuery, err)
			}
			results = append(results, denyResults...)
			continue
		}

		warnQuery := fmt.Sprintf("%s.warn[res]", parsedPolicy.Package.Path.String())
		warn, err := rego.New(
			rego.Compiler(compiler),
			rego.Query(warnQuery),
			rego.Input(resource),
		).Eval(ctx)

		if err != nil {
			return nil, fmt.Errorf("failed evaluating Rego warn rule: %s: %w", warnQuery, err)
		}

		warnValues, hasWarnValues := hasBindings(warn, varResult)
		if hasWarnValues {
			warnResults, err := valuesToResults(md, warnValues)
			if err != nil {
				return nil, fmt.Errorf("failed parsing warn rule result: %s: %w", warnQuery, err)
			}
			results = append(results, warnResults...)
			continue
		}

		results = append(results, Result{
			Metadata: md,
			Success:  true,
		})
	}

	return results, nil
}

func hasBinding(rs rego.ResultSet, key string) (map[string]interface{}, bool) {
	if rs == nil || len(rs) == 0 {
		return nil, false
	}
	binding, ok := rs[0].Bindings[key]
	return binding.(map[string]interface{}), ok
}

func hasBindings(rs rego.ResultSet, key string) ([]map[string]interface{}, bool) {
	if rs == nil || len(rs) == 0 {
		return nil, false
	}
	var values []map[string]interface{}

	for _, r := range rs {
		binding, ok := r.Bindings[key]
		if !ok {
			continue
		}
		value, ok := binding.(map[string]interface{})
		if !ok {
			continue
		}
		values = append(values, value)
	}
	return values, len(rs) == len(values)
}

func requiredStringValue(values map[string]interface{}, key string) (string, error) {
	value, ok := values[key]
	if !ok {
		return "", fmt.Errorf("required key not found: %s", key)
	}
	if value == nil {
		return "", fmt.Errorf("required value is nil for key: %s", key)
	}
	valueString, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("expected string got %T for key: %s", value, key)
	}
	if valueString == "" {
		return "", fmt.Errorf("required value is blank for key: %s", key)
	}
	return valueString, nil
}

func valuesToResults(md Metadata, values []map[string]interface{}) (Results, error) {
	var results Results
	var messages []string

	for _, value := range values {
		message, err := NewMessage(value)
		if err != nil {
			return nil, err
		}
		messages = append(messages, message)
	}

	results = append(results, Result{
		Metadata: md,
		Success:  false,
		Messages: messages,
	})
	return results, nil
}
