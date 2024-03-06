package policy

import (
	"context"
	"path/filepath"
	"sync"

	mp "github.com/aquasecurity/trivy/pkg/policy"
	"golang.org/x/xerrors"
)

const (
	BundleRepository = "ghcr.io/aquasecurity/trivy-policies"
)

type PolicyLoader struct {
	PolicyRepo string
	Cachedir   string
	mu         sync.Mutex
}

func NewPolicyLoader(pr string, cachedir string) *PolicyLoader {
	return &PolicyLoader{
		PolicyRepo: pr,
		Cachedir:   cachedir,
	}
}

func (pl *PolicyLoader) GetBuiltInPolicies(ctx context.Context) ([]string, error) {
	pl.mu.Lock()
	defer pl.mu.Unlock()

	client, err := mp.NewClient(pl.Cachedir, true, pl.PolicyRepo)
	if err != nil {
		return nil, xerrors.Errorf("policy client error: %w", err)
	}

	if err = client.DownloadBuiltinPolicies(ctx); err != nil {
		return nil, xerrors.Errorf("failed to download built-in policies: %w", err)
	}
	return client.LoadBuiltinPolicies()
}
