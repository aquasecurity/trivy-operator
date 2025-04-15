package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/go-logr/logr"
	"github.com/liamg/memoryfs"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/aquasecurity/trivy-operator/pkg/configauditreport"
	"github.com/aquasecurity/trivy-operator/pkg/kube"
	"github.com/aquasecurity/trivy-operator/pkg/plugins/trivy"
	"github.com/aquasecurity/trivy/pkg/iac/rego"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/kubernetes"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/options"
	"github.com/aquasecurity/trivy/pkg/iac/severity"
	"github.com/aquasecurity/trivy/pkg/mapfs"
)

const (
	keyPrefixPolicy  = "policy."
	keyPrefixLibrary = "library."
	keySuffixKinds   = ".kinds"
	keySuffixRego    = ".rego"

	PoliciesNotFoundError = "failed to load rego policies from [externalPolicies]: stat externalPolicies: file does not exist"
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

type k8sScanner interface {
	ScanFS(context.Context, fs.FS, string) (scan.Results, error)
}

type Policies struct {
	data           map[string]string
	log            logr.Logger
	cac            configauditreport.ConfigAuditConfig
	clusterVersion string
	policyLoader   Loader
	policyFS       *memoryfs.FS
	loaded         []string
	scanner        k8sScanner
}

func NewPolicies(data map[string]string, cac configauditreport.ConfigAuditConfig, log logr.Logger, pl Loader, serverVersion string) *Policies {
	return &Policies{
		data:           data,
		log:            log,
		cac:            cac,
		policyLoader:   pl,
		clusterVersion: serverVersion,
		policyFS:       memoryfs.New(),
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

// TODO: use loaded
func (p *Policies) Hash(kind string) (string, error) {
	policies, err := p.loadPolicies(kind)
	if err != nil {
		return "", fmt.Errorf("failed to load built-in / external policies: %s: %w", kind, err)
	}
	slices.Sort(policies)
	return kube.ComputeHash(policies), nil
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

func (p *Policies) Load() error {
	var err error

	if p.cac.GetUseBuiltinRegoPolicies() {
		p.loaded, _, err = p.policyLoader.GetPoliciesAndBundlePath()
		if err != nil {
			return err
		}
	}

	for _, lib := range p.Libraries() {
		p.loaded = append(p.loaded, lib)
	}

	for key, policy := range p.data {
		if !strings.HasSuffix(key, keySuffixRego) {
			continue
		}
		p.loaded = append(p.loaded, policy)
	}

	return nil
}

func (p *Policies) loadPolicies(kind string) ([]string, error) {
	// read external policies
	modByKind, err := p.ModulesByKind(kind)
	if err != nil {
		return nil, err
	}
	externalPolicies := make([]string, 0, len(modByKind))
	for _, mod := range modByKind {
		externalPolicies = append(externalPolicies, mod)
	}
	policies := make([]string, 0)
	// read built-in policies
	if p.cac.GetUseBuiltinRegoPolicies() {
		policies, _, err = p.policyLoader.GetPoliciesAndBundlePath()
		if err != nil {
			return nil, err
		}
	}
	if len(externalPolicies) > 0 {
		policies = append(policies, externalPolicies...)
	}
	return policies, nil
}

// Applicable check if policies exist either built in or via policies configmap
func (p *Policies) Applicable(resourceKind string) (bool, string, error) {
	HasExternalPolicies, err := p.ExternalPoliciesApplicable(resourceKind)
	if err != nil {
		return false, "", err
	}
	if !HasExternalPolicies && !p.cac.GetUseBuiltinRegoPolicies() && !p.cac.GetUseEmbeddedRegoPolicies() {
		return false, fmt.Sprintf("no policies found for kind %s", resourceKind), nil
	}
	return true, "", nil
}

func (p *Policies) ExternalPoliciesApplicable(resourceKind string) (bool, error) {
	policies, err := p.PoliciesByKind(resourceKind)
	if err != nil {
		return false, err
	}
	return len(policies) > 0, nil
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
func (p *Policies) Eval(ctx context.Context, resource client.Object, inputs ...[]byte) (scan.Results, error) {
	memfs := memoryfs.New()
	inputResource, err := resourceBytes(resource, inputs)
	if err != nil {
		return nil, err
	}

	// add resource input to in-memory filesystem
	if err := createPolicyInputFS(memfs, inputFolder, []string{string(inputResource)}, yamlExt); err != nil {
		return nil, err
	}

	if p.scanner == nil {
		if err := p.InitScanner(); err != nil {
			return nil, fmt.Errorf("init scanner: %w", err)
		}
	}

	scanResult, err := p.scanner.ScanFS(ctx, memfs, inputFolder)
	if err != nil {
		return nil, err
	}
	// special case when lib return nil for both checks and error
	if scanResult == nil {
		return nil, errors.New("failed to run policy checks on resources")
	}
	return scanResult, nil
}

func (p *Policies) InitScanner() error {
	hasPolicies := len(p.loaded) > 0
	if hasPolicies {
		// add policies to in-memory filesystem
		err := createPolicyInputFS(p.policyFS, policiesFolder, p.loaded, regoExt)
		if err != nil {
			return err
		}
	}
	dataFS, dataPaths, err := createDataFS([]string{}, p.clusterVersion)
	if err != nil {
		return fmt.Errorf("create data fs: %w", err)
	}
	so := p.scannerOptions(dataPaths, dataFS, hasPolicies)
	p.scanner = kubernetes.NewScanner(so...)
	return nil
}

func resourceBytes(resource client.Object, inputs [][]byte) ([]byte, error) {
	var inputResource []byte
	var err error
	if len(inputs) > 0 {
		inputResource = inputs[0]
	} else {
		if jsonManifest, ok := resource.GetAnnotations()["kubectl.kubernetes.io/last-applied-configuration"]; ok {
			inputResource = []byte(jsonManifest) // required for outdated-api when k8s convert resources
		} else {
			inputResource, err = json.Marshal(resource)
			if err != nil {
				return nil, err
			}
		}
	}
	return inputResource, nil
}

// GetResultID return the result id found in aliases (legacy) otherwise use AvdID
func (r *Policies) GetResultID(result scan.Result) string {
	id := result.Rule().AVDID
	if len(result.Rule().Aliases) > 0 {
		id = result.Rule().Aliases[0]
	}
	return id
}

func (r *Policies) HasSeverity(resultSeverity severity.Severity) bool {
	defaultSeverity := r.cac.GetSeverity()
	if defaultSeverity == "" {
		defaultSeverity = trivy.DefaultSeverity
	}
	return strings.Contains(defaultSeverity, string(resultSeverity))
}

func (p *Policies) scannerOptions(dataPaths []string, dataFS fs.FS, hasPolicies bool) []options.ScannerOption {
	optionsArray := []options.ScannerOption{
		rego.WithDataFilesystem(dataFS),
		rego.WithDataDirs(dataPaths...),
	}
	if !hasPolicies && p.cac.GetUseEmbeddedRegoPolicies() {
		return append(optionsArray, rego.WithEmbeddedPolicies(true), rego.WithEmbeddedLibraries(true))
	}
	return append(optionsArray,
		rego.WithPolicyFilesystem(p.policyFS),
		rego.WithPolicyDirs(policiesFolder), rego.WithPolicyNamespaces(externalPoliciesNamespace))
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

func createDataFS(dataPaths []string, k8sVersion string) (fs.FS, []string, error) {
	fsys := mapfs.New()

	// Create a virtual file for Kubernetes scanning
	if k8sVersion != "" {
		if err := fsys.MkdirAll("system", 0700); err != nil {
			return nil, nil, err
		}
		data := []byte(fmt.Sprintf(`{"k8s": {"version": %q}}`, k8sVersion))
		if err := fsys.WriteVirtualFile("system/k8s-version.json", data, 0600); err != nil {
			return nil, nil, err
		}
	}
	for _, path := range dataPaths {
		if err := fsys.CopyFilesUnder(path); err != nil {
			return nil, nil, err
		}
	}

	// data paths are no longer needed as fs.FS contains only needed files now.
	dataPaths = []string{"."}

	return fsys, dataPaths, nil
}
