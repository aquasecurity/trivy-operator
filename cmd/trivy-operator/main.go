package main

import (
	"fmt"
	"os"

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

	return operator.Start(ctrl.SetupSignalHandler(), buildInfo, operatorConfig)
}
