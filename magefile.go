//go:build mage

// This is a magefile, and is a "makefile for go".
// See https://magefile.org/

package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	//"github.com/aquasecurity/trivy/pkg/log"
	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
)

var (
	// Default targets
	ENV = map[string]string{
		"CGO_ENABLED": "0",
		"GOBIN":       LOCALBIN,
	}
	LINUX_ENV = map[string]string{
		"CGO_ENABLED": "0",
		"GOOS":        "linux",
	}

	GOBINENV = map[string]string{
		"GOBIN": goEnv("GOBIN"),
	}

	GOLOCALBINENV = map[string]string{
		"GOBIN": LOCALBIN,
	}

	// Variables
	KIND = "kind"

	KUBECONFIG = filepath.Join(os.Getenv("HOME"), ".kube", "config")

	GO111MODULE = "on" // Active module mode, as we use Go modules to manage dependencies
	GOPATH      = goEnv("GOPATH")
	GOBIN       = filepath.Join(goEnv("GOPATH"), "bin")
	GINKGO      = filepath.Join(PWD, "bin", "ginkgo")

	IMAGE_TAG                 = "dev"
	TRIVY_OPERATOR_IMAGE      = "aquasecurity/trivy-operator:" + IMAGE_TAG
	TRIVY_OPERATOR_IMAGE_UBI8 = "aquasecurity/trivy-operator:" + IMAGE_TAG + "-ubi8"

	MKDOCS_IMAGE = "aquasec/mkdocs-material:trivy-operator"
	MKDOCS_PORT  = 8000

	// ENVTEST_K8S_VERSION refers to the version of kubebuilder assets to be downloaded by envtest binary.
	ENVTEST_K8S_VERSION = "1.24.2"

	// Current working directory
	PWD = getWorkingDir()

	// Tool Binaries
	LOCALBIN       = filepath.Join(PWD, "bin")
	CONTROLLER_GEN = filepath.Join(LOCALBIN, "controller-gen")
	HELM_DOCS_GEN  = filepath.Join(LOCALBIN, "helm-docs")
	ENVTEST        = filepath.Join(LOCALBIN, "setup-envtest")

	// Controller Tools Version
	CONTROLLER_TOOLS_VERSION = "v0.14.0"
)

//func init() {
//	slog.SetDefault(log.New(log.NewHandler(os.Stderr, nil))) // stdout is suppressed in mage
//}

// Function to get the current working directory using os.Getwd()
func getWorkingDir() string {
	wd, err := os.Getwd()
	if err != nil {
		fmt.Println("Error getting the current working directory:", err)
		os.Exit(1)
	}
	return wd
}

type Build mg.Namespace

// Target for building trivy-operator binary.
func (b Build) Binary() error {
	fmt.Println("Building trivy-operator binary...")
	return sh.RunWithV(LINUX_ENV, "go", "build", "-o", "./bin/trivy-operator", "./cmd/trivy-operator/main.go")
}

// Target for installing Ginkgo CLI.
func getGinkgo() error {
	fmt.Println("Installing Ginkgo CLI...")
	return sh.RunWithV(ENV, "go", "install", "github.com/onsi/ginkgo/v2/ginkgo")
}

// Target for installing quicktemplate compiler.
func getQTC() error {
	fmt.Println("Installing quicktemplate compiler...")
	return sh.RunWithV(ENV, "go", "install", "github.com/valyala/quicktemplate/qtc")
}

// Target for converting quicktemplate files (*.qtpl) into Go code.
func compileTemplates() error {
	fmt.Println("Converting quicktemplate files to Go code...")
	return sh.RunWithV(ENV, filepath.Join(GOBIN, "qtc"))
}

type Test mg.Namespace

// Target for running unit tests.
func (t Test) Unit() error {
	fmt.Println("Running tests...")
	return sh.RunWithV(ENV, "go", "test", "-v", "-short", "-timeout", "60s", "-coverprofile=coverage.txt", "./...")
}

// Target for running integration tests for Trivy Operator.
func (t Test) Integration() error {
	fmt.Println("Running integration tests for Trivy Operator...")
	mg.Deps(checkKubeconfig, getGinkgo)
	return sh.RunV(GINKGO, "-coverprofile=coverage.txt",
		"-coverpkg=github.com/aquasecurity/trivy-operator/pkg/operator,"+
			"github.com/aquasecurity/trivy-operator/pkg/operator/predicate,"+
			"github.com/aquasecurity/trivy-operator/pkg/operator/controller,"+
			"github.com/aquasecurity/trivy-operator/pkg/plugin,"+
			"github.com/aquasecurity/trivy-operator/pkg/plugin/trivy,"+
			"github.com/aquasecurity/trivy-operator/pkg/configauditreport,"+
			"github.com/aquasecurity/trivy-operator/pkg/vulnerabilityreport",
		"./tests/itest/trivy-operator")
}

// Target for checking if KUBECONFIG environment variable is set.
func checkKubeconfig() error {
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		return fmt.Errorf("Environment variable KUBECONFIG is not set")
	}
	fmt.Println("KUBECONFIG=", kubeconfig)
	return nil
}

// Target for removing build artifacts
func (t Tool) Clean() {
	fmt.Println("Removing build artifacts...")
	removeDir(filepath.Join(".", "bin"))
	removeDir(filepath.Join(".", "dist"))
}

// Target for building Docker images for all binaries
func (b Build) DockerAll() {
	fmt.Println("Building Docker images for all binaries...")
	b.Docker()
	b.DockerUbi8()
}

// Target for building Docker image for trivy-operator
func (b Build) Docker() error {
	fmt.Println("Building Docker image for trivy-operator...")
	return sh.RunV("docker", "build", "--no-cache", "-t", TRIVY_OPERATOR_IMAGE, "-f", "build/trivy-operator/Dockerfile", "bin")
}

// Target for building Docker image for trivy-operator ubi8
func (b Build) DockerUbi8() error {
	fmt.Println("Building Docker image for trivy-operator ubi8...")
	return sh.RunV("docker", "build", "--no-cache", "-f", "build/trivy-operator/Dockerfile.ubi8", "-t", TRIVY_OPERATOR_IMAGE_UBI8, "bin")
}

// Target for loading Docker images into the KIND cluster
func (b Build) KindLoadImages() error {
	fmt.Println("Loading Docker images into the KIND cluster...")
	mg.Deps(b.Docker, b.DockerUbi8)
	return sh.RunV(KIND, "load", "docker-image", TRIVY_OPERATOR_IMAGE, TRIVY_OPERATOR_IMAGE_UBI8)
}

type Docs mg.Namespace

// Target for running MkDocs development server to preview the operator documentation page
func (d Docs) Serve() error {
	fmt.Println("Running MkDocs development server...")
	err := sh.RunV("docker", "build", "-t", MKDOCS_IMAGE, "-f", "build/mkdocs-material/Dockerfile", "build/trivy-operator")
	if err != nil {
		return err
	}
	return sh.RunV("docker", "run", "--name", "mkdocs-serve", "--rm", "-v", fmt.Sprintf("%s:/docs", PWD), "-p", fmt.Sprintf("%d:8000", MKDOCS_PORT), MKDOCS_IMAGE)
}

// Target for installing the labeler tool
func installLabeler() error {
	fmt.Println("Installing the labeler tool...")
	return sh.RunWithV(GOBINENV, "go", "install", "github.com/knqyf263/labeler@latest")
}

// Target for creating the LOCALBIN directory
func localBin() error {
	fmt.Println("Creating LOCALBIN directory...")
	return os.MkdirAll(LOCALBIN, os.ModePerm)
}

// Target for downloading controller-gen locally if necessary
func controllerGen() error {
	mg.Deps(localBin)
	fmt.Println("Downloading controller-gen...")
	return sh.RunWithV(GOLOCALBINENV, "go", "install", "sigs.k8s.io/controller-tools/cmd/controller-gen@"+CONTROLLER_TOOLS_VERSION)
}

// Target for downloading envtest-setup locally if necessary
func (t Test) envTestBin() error {
	mg.Deps(localBin)
	fmt.Println("Downloading envtest-setup...")
	return sh.RunWithV(GOLOCALBINENV, "go", "install", "sigs.k8s.io/controller-runtime/tools/setup-envtest@latest")
}

type Generate mg.Namespace

// Target for verifying generated artifacts
func (g Generate) Verify() {
	fmt.Println("Verifying generated artifacts...")
	mg.Deps(g.All, g.verifyFilesDiff)
}

func (g Generate) verifyFilesDiff() error {
	command := "./hack/verify-generated.sh"
	return sh.RunV("bash", "-c", command)
}

// Target for generating code and manifests
func (g Generate) Code() error {
	fmt.Println("Generating code and manifests...")
	mg.Deps(controllerGen)
	return sh.RunV(CONTROLLER_GEN, "object:headerFile=hack/boilerplate.go.txt", "paths=./pkg/...", "+rbac:roleName=trivy-operator", "output:rbac:artifacts:config=deploy/helm/generated")
}

// Target for generating CRDs and updating static YAML
func (g Generate) Manifests() error {
	fmt.Println("Generating CRDs and updating static YAML...")
	mg.Deps(controllerGen)
	err := sh.RunV(CONTROLLER_GEN, "crd:allowDangerousTypes=true", "paths=./pkg/apis/...", "output:crd:artifacts:config=deploy/helm/crds")
	if err != nil {
		return err
	}
	return sh.RunV("./hack/update-static.yaml.sh")
}

// Target for generating all artifacts
func (g Generate) All() {
	fmt.Println("Generating all artifacts...")
	mg.Deps(g.Code, g.Manifests)
}

// Target for generating Helm documentation
func (g Generate) Docs() error {
	fmt.Println("Generating Helm documentation...")
	err := sh.RunWithV(GOLOCALBINENV, "go", "install", "github.com/norwoodj/helm-docs/cmd/helm-docs@latest")
	if err != nil {
		return err
	}
	return sh.RunV(HELM_DOCS_GEN, "./deploy")
}

// Target for verifying generated Helm documentation
func (g Generate) VerifyDocs() error {
	fmt.Println("Verifying generated Helm documentation...")
	mg.Deps(g.Docs)
	return g.verifyFilesDiff()
}

// GoEnv returns the value of a Go environment variable.
func goEnv(envVar string) string {
	cmd := exec.Command("go", "env", envVar)
	output, err := cmd.Output()
	if err != nil {
		fmt.Printf("Error retrieving Go environment variable %s: %v\n", envVar, err)
		os.Exit(1)
	}
	return string(output)
}

// Target for running kubernetes envtests.
func (t Test) Envtest() error {
	mg.Deps(t.envTestBin)
	output, err := sh.Output(filepath.Join(PWD, "bin", "setup-envtest"), "use", ENVTEST_K8S_VERSION, "-p", "path")
	if err != nil {
		return err
	}
	mg.Deps(t.envTestBin)
	return sh.RunWithV(map[string]string{"KUBEBUILDER_ASSETS": output}, "go", "test", "-v", "-timeout", "60s", "-coverprofile=coverage.txt", "./tests/envtest/...")
}

// removeDir removes the directory at the given path.
func removeDir(path string) error {
	return sh.RunV("rm", "-r", path)
}

type Tool mg.Namespace

// Target install Aqua tools if not installed
func (Tool) Aqua() error {
	if exists(filepath.Join(GOBIN, "aqua")) {
		return nil
	}
	return sh.Run("go", "install", "github.com/aquaproj/aqua/v2/cmd/aqua@v2.2.1")
}
func exists(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
}

type Lint mg.Namespace

// Run runs linters
func (Lint) Run() error {
	//mg.Deps(Tool{}.GolangciLint)
	return sh.RunV("golangci-lint", "run")
}

// Fix auto fixes linters
func (Lint) Fix() error {
	//mg.Deps(Tool{}.GolangciLint)
	return sh.RunV("golangci-lint", "run", "--fix")
}

// GolangciLint installs golangci-lint
func (t Tool) GolangciLint() error {
	const version = "v1.61.0"
	bin := filepath.Join(GOBIN, "golangci-lint")
	if exists(bin) && t.matchGolangciLintVersion(bin, version) {
		return nil
	}
	command := fmt.Sprintf("curl -sfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b %s %s", GOBIN, version)
	return sh.Run("bash", "-c", command)
}

func (Tool) matchGolangciLintVersion(bin, version string) bool {
	out, err := sh.Output(bin, "version", "--format", "json")
	if err != nil {
		slog.Error("Unable to get golangci-lint version", slog.Any("err", err))
		return false
	}
	var output struct {
		Version string `json:"Version"`
	}
	if err = json.Unmarshal([]byte(out), &output); err != nil {
		slog.Error("Unable to parse golangci-lint version", slog.Any("err", err))
		return false
	}

	version = strings.TrimPrefix(version, "v")
	if output.Version != version {
		slog.Info("golangci-lint version mismatch", slog.String("expected", version), slog.String("actual", output.Version))
		return false
	}
	return true
}
