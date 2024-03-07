package policy

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	mp "github.com/aquasecurity/trivy/pkg/policy"
	"github.com/bluele/gcache"
	"golang.org/x/xerrors"
)

const (
	bundlePolicies = "bundlePolicies"
)

type Loader interface {
	GetPolicies() ([]string, error)
}

type policyLoader struct {
	PolicyRepo string
	mutex      sync.RWMutex
	cache      gcache.Cache
	expiration *time.Duration
	options    []mp.Option
}

func NewPolicyLoader(pr string, cache gcache.Cache, opts ...mp.Option) Loader {
	expiration := 24 * time.Hour
	return &policyLoader{
		PolicyRepo: pr,
		cache:      cache,
		options:    opts,
		expiration: &expiration,
	}
}

func (pl *policyLoader) GetPolicies() ([]string, error) {
	var policies []string
	var ok bool
	val, err := pl.getPoliciesFromCache()
	if err != nil {
		if !errors.Is(err, gcache.KeyNotFoundError) {
			return []string{}, err
		}
		policies, err = pl.LoadPolicies()
		if err != nil {
			return []string{}, nil
		}
		return policies, nil
	}
	if policies, ok = val.([]string); !ok {
		return []string{}, fmt.Errorf("failed to get policies from cache")
	}
	return policies, nil

}

func (pl *policyLoader) getPoliciesFromCache() (interface{}, error) {
	pl.mutex.RLock()
	defer pl.mutex.RUnlock()
	return pl.cache.Get(bundlePolicies)
}

func (pl *policyLoader) LoadPolicies() ([]string, error) {
	pl.mutex.Lock()
	defer pl.mutex.Unlock()

	policyPath, err := pl.getBuiltInPolicies(context.Background())
	if err != nil {
		return []string{}, fmt.Errorf("failed to donwload policies: %w", err)
	}
	policiesData, err := LoadPoliciesData(policyPath)
	if err != nil {
		return []string{}, fmt.Errorf("failed to donwload policies: %w", err)
	}
	_ = pl.cache.SetWithExpire(bundlePolicies, policiesData, *pl.expiration)
	return policiesData, nil
}

func (pl *policyLoader) getBuiltInPolicies(ctx context.Context) ([]string, error) {
	client, err := mp.NewClient("tmp", true, pl.PolicyRepo, pl.options...)
	if err != nil {
		return nil, xerrors.Errorf("policy client error: %w", err)
	}

	if err = client.DownloadBuiltinPolicies(ctx); err != nil {
		return nil, xerrors.Errorf("failed to download built-in policies: %w", err)
	}
	return client.LoadBuiltinPolicies()
}

func LoadPoliciesData(policyPath []string) ([]string, error) {
	policiesList := []string{}
	fileList := []string{}
	err := filepath.Walk(policyPath[0], func(path string, f os.FileInfo, err error) error {
		if strings.Contains(path, "/kubernetes/") { // load only k8s policies
			fileList = append(fileList, path)
		}
		return nil
	})
	if err != nil {
		return []string{}, fmt.Errorf("failed to walk policy path: %w", err)
	}
	for _, file := range fileList {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		policiesList = append(policiesList, string(data))
	}
	return policiesList, nil
}
