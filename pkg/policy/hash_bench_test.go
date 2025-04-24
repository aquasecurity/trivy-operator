package policy

import (
	"github.com/aquasecurity/trivy-operator/pkg/plugins/trivy"
	"github.com/aquasecurity/trivy-operator/pkg/utils"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/bluele/gcache"
	ctrl "sigs.k8s.io/controller-runtime"
	"strings"
	"testing"
	"time"
)

var (
	k8sresources = []string{
		"Pod",
		"Deployment",
		"DaemonSet",
		"StatefulSet",
		"ReplicaSet",
	}
)

type testConfig struct {
	builtInPolicies  bool
	embeddedPolicies bool
}

func newTestConfig(builtInPolicies bool) testConfig {
	return testConfig{builtInPolicies: builtInPolicies}
}

// GetUseBuiltinRegoPolicies return trivy config which associated to configauditreport plugin
func (tc testConfig) GetUseBuiltinRegoPolicies() bool {
	return tc.builtInPolicies
}

// GetUseBuiltinRegoPolicies return trivy config which associated to configauditreport plugin
func (tc testConfig) GetUseEmbeddedRegoPolicies() bool {
	return tc.embeddedPolicies
}

// GetSupportedConfigAuditKinds list of supported kinds to be scanned by the config audit scanner
func (tc testConfig) GetSupportedConfigAuditKinds() []string {
	return utils.MapKinds(strings.Split(trivy.SupportedConfigAuditKinds, ","))
}

func (tc testConfig) GetSeverity() string {
	return trivy.KeyTrivySeverity
}

func benchmarkHash10000(b *testing.B, p *Policies) {
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < 10000; i++ {
		for _, resource := range k8sresources {
			_, _ = p.Hash(resource)
		}
	}
}

func BenchmarkPolicies_Hash(b *testing.B) {
	expiration := 24 * time.Hour
	pl := NewPolicyLoader("", gcache.New(2).LRU().Build(), types.RegistryOptions{})
	p := NewPolicies(map[string]string{
		"policy.valid.rego":  "<REGO_CONTENT>",
		"policy.valid.kinds": "Pod",
	}, newTestConfig(true), ctrl.Log.WithName("policy logger"), pl, "v1.23.0", &expiration)
	benchmarkHash10000(b, p)
}

func BenchmarkPolicies_HashWithoutCache(b *testing.B) {
	expiration := 24 * time.Hour
	pl := NewPolicyLoader("", gcache.New(2).LRU().Build(), types.RegistryOptions{})
	p := NewPolicies(map[string]string{
		"policy.valid.rego":  "<REGO_CONTENT>",
		"policy.valid.kinds": "Pod",
	}, newTestConfig(true), ctrl.Log.WithName("policy logger"), pl, "v1.23.0", &expiration)
	p.cache = nil
	benchmarkHash10000(b, p)
}

func BenchmarkPolicies_HashWithoutCacheAndIncorrectSize(b *testing.B) {
	expiration := 24 * time.Hour
	pl := NewPolicyLoader("", gcache.New(1).LRU().Build(), types.RegistryOptions{})
	p := NewPolicies(map[string]string{
		"policy.valid.rego":  "<REGO_CONTENT>",
		"policy.valid.kinds": "Pod",
	}, newTestConfig(true), ctrl.Log.WithName("policy logger"), pl, "v1.23.0", &expiration)
	p.cache = nil
	benchmarkHash10000(b, p)
}
