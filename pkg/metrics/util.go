package metrics

import (
	"regexp"
	"strings"
)

var (
	matchAllCap        = regexp.MustCompile("([a-z0-9])([A-Z])")
	invalidLabelCharRE = regexp.MustCompile(`[^a-zA-Z0-9_]`)
)

func toSnakeCase(s string) string {
	snake := matchAllCap.ReplaceAllString(s, "${1}_${2}")
	return strings.ToLower(snake)
}

func sanitizeLabelName(s string) string {
	return toSnakeCase(invalidLabelCharRE.ReplaceAllString(s, "_"))
}
