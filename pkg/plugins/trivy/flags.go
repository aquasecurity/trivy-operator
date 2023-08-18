package trivy

import (
	"github.com/Masterminds/semver"
)

func compareTagVersion(currentTag string, contraint string) bool {
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

// Slow determine if to use the slow flag (improve memory footprint)
func Slow(c Config) string {
	tag, err := c.GetImageTag()
	if err != nil {
		return ""
	}
	// support backward compatibility with older tags
	if compareTagVersion(tag, "< 0.35.0") {
		return ""
	}
	if c.GetSlow() {
		return "--slow"
	}
	return ""
}

// Scanners use scanners flag
func Scanners(c Config) string {
	tag, err := c.GetImageTag()
	if err != nil {
		return "--scanners"
	}
	// support backward compatibility with older tags
	if compareTagVersion(tag, "< 0.37.0") {
		return "--security-checks"
	}
	return "--scanners"
}

// SkipDBUpdate skip update flag
func SkipDBUpdate(c Config) string {
	tag, err := c.GetImageTag()
	if err != nil {
		return "--skip-db-update"
	}
	// support backward compatibility with older tags
	if compareTagVersion(tag, "< 0.37.0") {
		return "--skip-update"
	}
	return "--skip-db-update"
}

// SkipJavaDBUpdate skip update flag
func SkipJavaDBUpdate(c Config) string {
	if c.GetSkipJavaDBUpdate() {
		tag, err := c.GetImageTag()
		if err != nil {
			return "--skip-java-db-update"
		}
		// support backward compatibility with older tags
		if compareTagVersion(tag, "< 0.37.0") {
			return ""
		}
		return "--skip-java-db-update"
	}
	return ""
}

// MultiSecretSupport validate if trivy multi secret support
func MultiSecretSupport(c Config) bool {
	tag, err := c.GetImageTag()
	if err != nil {
		return true
	}
	// support backward compatibility with older tags
	if compareTagVersion(tag, "< 0.38.0") {
		return false
	}
	return true
}
