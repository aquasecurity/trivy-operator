package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"strings"

	"github.com/aquasecurity/trivy-operator/pkg/configauditreport"

	"github.com/aquasecurity/defsec/pkg/scanners"
	"github.com/aquasecurity/defsec/pkg/scanners/rbac"
	"github.com/go-logr/logr"
	"github.com/liamg/memoryfs"

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

	PoliciesNotFoundError = "no policies found"
)

const (
	kindAny                   = "*"
	kindWorkload              = "Workload"
	inputFolder               = "inputs"
	policiesFolder            = "externalPolicies"
	regoExt                   = "rego"
	yamlExt                   = "yaml"
	externalPoliciesNamespace = "trivyoperator"
)

type Policies struct {
	data map[string]string
	log  logr.Logger
	cac  configauditreport.ConfigAuditConfig
}

func NewPolicies(data map[string]string, cac configauditreport.ConfigAuditConfig, log logr.Logger) *Policies {
	return &Policies{
		data: data,
		log:  log,
		cac:  cac,
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
func (p *Policies) ModulePolicyByKind(kind string) ([]string, error) {
	modByKind, err := p.ModulesByKind(kind)
	if err != nil {
		return nil, err
	}
	policy := make([]string, 0, len(modByKind))
	for _, mod := range modByKind {
		policy = append(policy, mod)
	}
	return policy, nil
}

// Applicable check if policies exist either built in or via policies configmap
func (p *Policies) Applicable(resource client.Object) (bool, string, error) {
	resourceKind := resource.GetObjectKind().GroupVersionKind().Kind
	if resourceKind == "" {
		return false, "", errors.New("resource kind must not be blank")
	}
	policies, err := p.PoliciesByKind(resourceKind)
	if err != nil {
		return false, "", err
	}
	if len(policies) == 0 && !p.cac.GetUseBuiltinRegoPolicies() {
		return false, fmt.Sprintf("no policies found for kind %s", resource.GetObjectKind().GroupVersionKind().Kind), nil
	}
	return true, "", nil
}

// SupportedKind scan policies supported for this kind
func (p *Policies) SupportedKind(resource client.Object, rbacDEnable bool) (bool, error) {
	resourceKind := resource.GetObjectKind().GroupVersionKind().Kind
	if resourceKind == "" {
		return false, errors.New("resource kind must not be blank")
	}
	for _, kind := range p.cac.GetSupportedConfigAuditKinds() {
		if kind == resourceKind && !p.rbacDisabled(rbacDEnable, kind) {
			return true, nil
		}
	}
	return false, nil
}

func (p *Policies) rbacDisabled(rbacEnable bool, kind string) bool {
	if !rbacEnable && kube.IsRoleTypes(kube.Kind(kind)) {
		return true
	}
	return false
}

// Eval evaluates Rego policies with Kubernetes resource client.Object as input.
func (p *Policies) Eval(ctx context.Context, resource client.Object) (scan.Results, error) {
	if resource == nil {
		return nil, fmt.Errorf("resource must not be nil")
	}
	resourceKind := resource.GetObjectKind().GroupVersionKind().Kind
	if resourceKind == "" {
		return nil, fmt.Errorf("resource kind must not be blank")
	}
	externalPolicies, err := p.ModulePolicyByKind(resourceKind)
	if err != nil {
		return nil, fmt.Errorf("failed listing externalPolicies by kind: %s: %w", resourceKind, err)
	}
	memfs := memoryfs.New()
	hasExternalPolicies := len(externalPolicies) > 0
	if !hasExternalPolicies && !p.cac.GetUseBuiltinRegoPolicies() {
		return scan.Results{}, fmt.Errorf(PoliciesNotFoundError)
	}
	if hasExternalPolicies {
		// add externalPolicies files
		err = createPolicyInputFS(memfs, policiesFolder, externalPolicies, regoExt)
		if err != nil {
			return nil, err
		}
	}
	inputResource, err := json.Marshal(resource)
	if err != nil {
		return nil, err
	}
	// add input files
	err = createPolicyInputFS(memfs, inputFolder, []string{string(inputResource)}, yamlExt)
	if err != nil {
		return nil, err
	}
	scanner := scannerByType(resourceKind, getScannerOptions(hasExternalPolicies, p.cac.GetUseBuiltinRegoPolicies(), policiesFolder))
	scanResult, err := scanner.ScanFS(ctx, memfs, inputFolder)
	if err != nil {
		return nil, err
	}
	//special case when lib return nil for both checks and error
	if scanResult == nil && err == nil {
		return nil, fmt.Errorf("failed to run policy checks on resources")
	}
	return scanResult, nil
}

// GetResultID return the result id found in aliases (legacy) otherwise use AvdID
func (r *Policies) GetResultID(result scan.Result) string {
	id := result.Rule().AVDID
	if len(result.Rule().Aliases) > 0 {
		id = result.Rule().Aliases[0]
	}
	return id
}

func scannerByType(resourceKind string, scannerOptions []options.ScannerOption) scanners.FSScanner {
	if strings.Contains(resourceKind, "Role") {
		return rbac.NewScanner(scannerOptions...)
	}
	return kubernetes.NewScanner(scannerOptions...)
}

func getScannerOptions(hasExternalPolicies bool, useDefaultPolicies bool, policiesFolder string) []options.ScannerOption {
	optionsArray := []options.ScannerOption{options.ScannerWithEmbeddedPolicies(useDefaultPolicies)}
	if hasExternalPolicies {
		optionsArray = append(optionsArray, options.ScannerWithPolicyDirs(policiesFolder))
		optionsArray = append(optionsArray, options.ScannerWithPolicyNamespaces(externalPoliciesNamespace))
	}
	return optionsArray
}

func createPolicyInputFS(memfs *memoryfs.FS, folderName string, fileData []string, ext string) error {
	if len(fileData) == 0 {
		return nil
	}
	if err := memfs.MkdirAll(filepath.Base(folderName), 0o700); err != nil {
		return err
	}
	for index, file := range fileData {
		if err := memfs.WriteFile(path.Join(folderName, fmt.Sprintf("file_%d.%s", index, ext)), []byte(file), 0o644); err != nil {
			return err
		}
	}
	return nil
}
