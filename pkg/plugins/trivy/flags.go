package trivy

import (
	"github.com/Masterminds/semver"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
)

func validVersion(currentTag string, contraint string) bool {
	c, err := semver.NewConstraint(contraint)
	if err != nil {
		return false
	}

	v, err := semver.NewVersion(currentTag)
	if err != nil {
		return false
	}
	// Check if the version meets the constraints. The a variable will be true.
	return c.Check(v)
}

func GetConfig(ctx trivyoperator.PluginContext) (Config, error) {
	pluginConfig, err := ctx.GetConfig()
	if err != nil {
		return Config{}, err
	}
	return Config{PluginConfig: pluginConfig}, nil
}

// Slow determine if to use the slow flag (improve memory footprint)
func Slow(ctx trivyoperator.PluginContext) string {
	c, err := GetConfig(ctx)
	if err != nil {
		return ""
	}
	tag, err := c.GetImageTag()
	if err != nil {
		return ""
	}
	// support backward competability with older tags
	if !validVersion(tag, ">= 0.35.0") {
		return ""
	}
	if c.GetSlow() {
		return "--slow"
	}
	return ""
}

// Scanners use scanners flag
func Scanners(ctx trivyoperator.PluginContext) string {
	c, err := GetConfig(ctx)
	if err != nil {
		return "--scanners"
	}
	tag, err := c.GetImageTag()
	if err != nil {
		return "--scanners"
	}
	// support backward competability with older tags
	if !validVersion(tag, ">= 0.37.0") {
		return "--security-checks"
	}
	return "--scanners"
}

// SkipDBUpdate skip update flag
func SkipDBUpdate(ctx trivyoperator.PluginContext) string {
	c, err := GetConfig(ctx)
	if err != nil {
		return "--skip-db-update"
	}
	tag, err := c.GetImageTag()
	if err != nil {
		return "--skip-db-update"
	}
	// support backward competability with older tags
	if !validVersion(tag, ">= 0.37.0") {
		return "--skip-update"
	}
	return "--skip-db-update"
}
