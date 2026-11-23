package main

import (
	"crypto/fips140"
	"fmt"
	"os"
	"runtime/debug"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	"github.com/aquasecurity/trivy-operator/pkg/operator"
	"github.com/aquasecurity/trivy-operator/pkg/operator/etc"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"

	_ "go.uber.org/automaxprocs"
)

var (
	// These variables are populated by GoReleaser via ldflags
	version = "dev"
	commit  = "none"
	date    = "unknown"

	buildInfo = trivyoperator.BuildInfo{
		Version: version,
		Commit:  commit,
		Date:    date,
	}
)

var (
	setupLog = log.Log.WithName("main")
)

// main is the entrypoint of the Trivy Operator executable command.
func main() {
	// Fetch operator configuration early.
	operatorConfig, err := etc.GetOperatorConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error getting operator config: %v\n", err)
		os.Exit(1)
	}

	// Initialize the logger based on the LogDevMode from the config.
	log.SetLogger(zap.New(zap.UseDevMode(operatorConfig.LogDevMode)))

	if err := run(operatorConfig); err != nil {
		fmt.Fprintf(os.Stderr, "unable to run trivy operator: %v\n", err)
		os.Exit(1)
	}
}

func run(operatorConfig etc.Config) error {
	setupLog.Info("Starting operator", "buildInfo", buildInfo)
	if err := checkFIPS(); err != nil {
		return err
	}

	return operator.Start(ctrl.SetupSignalHandler(), buildInfo, operatorConfig)
}

// checkFIPS logs the FIPS 140-3 mode and refuses to start a binary built with
// the FIPS 140-3 module (GOFIPS140) when the mode was disabled at runtime,
// e.g. with GODEBUG=fips140=off, so that the FIPS image never runs with
// non-validated cryptography. A binary built without the module may still run
// with GODEBUG=fips140=on, but it then uses a non-validated module, and the
// log message says so.
func checkFIPS() error {
	var buildModule string
	if info, ok := debug.ReadBuildInfo(); ok {
		buildModule = fipsBuildModule(info)
	}

	if fips140.Enabled() {
		setupLog.Info(fipsEnabledMessage(buildModule),
			"moduleVersion", fips140.Version(),
			"enforced", fips140.Enforced())
		return nil
	}
	return fipsDisabledError(buildModule)
}

// fipsEnabledMessage returns the startup log message for enabled FIPS 140-3
// mode. For a binary built without the FIPS 140-3 module it warns that the
// module is not validated, so the log is not mistaken for FIPS 140-3 compliance.
func fipsEnabledMessage(buildModule string) string {
	if buildModule == "" {
		return "WARNING: FIPS 140-3 mode enabled with a non-validated module: " +
			"use the -ubi9-fips image for FIPS 140-3 compliance"
	}
	return "FIPS 140-3 mode enabled"
}

// fipsDisabledError returns an error if FIPS 140-3 mode is disabled in a binary
// built with the FIPS 140-3 module buildModule, and nil for a binary built
// without it.
func fipsDisabledError(buildModule string) error {
	if buildModule == "" {
		return nil
	}
	return fmt.Errorf("FIPS 140-3 mode is disabled, but the binary was built with the FIPS 140-3 module %s "+
		"and cannot run without it: remove fips140=off from the GODEBUG environment variable", buildModule)
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
