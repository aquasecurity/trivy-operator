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

	"github.com/bluele/gcache"
	"github.com/go-logr/logr"
	"golang.org/x/xerrors"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
	mp "github.com/aquasecurity/trivy/pkg/policy"
)

const (
	bundlePolicies = "bundlePolicies"
	bundlePath     = "bundlePath"
)

type Loader interface {
	GetPoliciesAndBundlePath() ([]string, []string, error)
}

type policyLoader struct {
	PolicyRepo      string
	mutex           sync.RWMutex
	cache           gcache.Cache
	expiration      *time.Duration
	options         []mp.Option
	logger          logr.Logger
	RegistryOptions types.RegistryOptions
}

func NewPolicyLoader(pr string, cache gcache.Cache, registryOptions types.RegistryOptions, opts ...mp.Option) Loader {
	expiration := 24 * time.Hour
	return &policyLoader{
		PolicyRepo:      pr,
		cache:           cache,
		options:         opts,
		expiration:      &expiration,
		logger:          ctrl.Log.WithName("policyLoader"),
		RegistryOptions: registryOptions,
	}
}

func (pl *policyLoader) GetPoliciesAndBundlePath() ([]string, []string, error) {
	log := pl.logger.WithName("Get misconfig bundle policies")
	var policies []string
	var bundlePaths []string
	var ok bool
	plc, bndl, err := pl.getPoliciesFromCache()
	if err != nil {
		if !errors.Is(err, gcache.KeyNotFoundError) {
			return []string{}, []string{}, err
		}
		policies, bundlePaths, err = pl.LoadPoliciesAndCommands()
		if err != nil {
			log.V(1).Error(err, "failed to load policies")
			return []string{}, []string{}, nil
		}
		return policies, bundlePaths, nil
	}
	if policies, ok = plc.([]string); !ok {
		return []string{}, []string{}, errors.New("failed to get policies from cache")
	}
	if bundlePaths, ok = bndl.([]string); !ok {
		return []string{}, []string{}, errors.New("failed to get bundlePath from cache")
	}
	return policies, bundlePaths, nil

}

func (pl *policyLoader) getPoliciesFromCache() (any, any, error) {
	pl.mutex.RLock()
	defer pl.mutex.RUnlock()
	policies, err := pl.cache.Get(bundlePolicies)
	if err != nil {
		return nil, nil, err
	}
	bundlePath, err := pl.cache.Get(bundlePath)
	if err != nil {
		return nil, nil, err
	}
	return policies, bundlePath, nil
}

func (pl *policyLoader) LoadPoliciesAndCommands() ([]string, []string, error) {
	pl.mutex.Lock()
	defer pl.mutex.Unlock()
	bundlePaths, err := pl.getBuiltInPolicies(context.Background())
	if err != nil {
		return []string{}, []string{}, fmt.Errorf("failed to download policies: %w", err)
	}
	contentData, err := LoadPoliciesData(bundlePaths)
	if err != nil {
		return []string{}, []string{}, fmt.Errorf("failed to download policies: %w", err)
	}
	_ = pl.cache.SetWithExpire(bundlePolicies, contentData, *pl.expiration)
	_ = pl.cache.SetWithExpire(bundlePath, bundlePaths, *pl.expiration)
	return contentData, bundlePaths, nil
}

func (pl *policyLoader) getBuiltInPolicies(ctx context.Context) ([]string, error) {
	client, err := mp.NewClient("tmp", true, pl.PolicyRepo, pl.options...)
	if err != nil {
		return nil, xerrors.Errorf("policy client error: %w", err)
	}

	if err = client.DownloadBuiltinChecks(ctx, pl.RegistryOptions); err != nil {
		return nil, xerrors.Errorf("failed to download built-in policies: %w", err)
	}
	return client.LoadBuiltinChecks()
}

func LoadPoliciesData(policyPath []string) ([]string, error) {
	var policiesList []string
	var fileList []string
	err := filepath.Walk(policyPath[0], func(path string, f os.FileInfo, err error) error {
		if strings.Contains(path, "policies/kubernetes/") { // load only k8s policies
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
