package main

import (
	"crypto/fips140"
	"runtime/debug"
)

// logFIPSStatus logs whether FIPS 140-3 mode is enabled. For a binary built
// with GOFIPS140, it also logs when the mode was disabled at runtime
// (e.g. GODEBUG=fips140=off), so that this does not go unnoticed.
func logFIPSStatus() {
	if fips140.Enabled() {
		setupLog.Info("FIPS 140-3 mode enabled",
			"moduleVersion", fips140.Version(),
			"enforced", fips140.Enforced())
		return
	}

	info, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}
	if module := fipsBuildModule(info); module != "" {
		setupLog.Info("FIPS 140-3 mode disabled, although the binary was built with the FIPS 140-3 module",
			"buildModule", module)
	}
}

// fipsBuildModule returns the GOFIPS140 value the binary was built with,
// or an empty string if it was built without the FIPS 140-3 module.
func fipsBuildModule(info *debug.BuildInfo) string {
	for _, s := range info.Settings {
		if s.Key == "GOFIPS140" && s.Value != "off" {
			return s.Value
		}
	}
	return ""
}
