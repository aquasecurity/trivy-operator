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
	logFIPSStatus()

	return operator.Start(ctrl.SetupSignalHandler(), buildInfo, operatorConfig)
}

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
