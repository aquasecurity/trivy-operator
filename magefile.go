//go:build mage

// This is a magefile, and is a "makefile for go".
// See https://magefile.org/

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/magefile/mage/mg"
)

var (
	// Default targets
	Default = Build

	// Variables
	DOCKER = "docker"
	KIND   = "kind"

	KUBECONFIG = filepath.Join(os.Getenv("HOME"), ".kube", "config")

	GO111MODULE = "on" // Active module mode, as we use Go modules to manage dependencies
	GOPATH      = goEnv("GOPATH")
	GOBIN       = filepath.Join(goEnv("GOPATH"), "bin")
	GINKGO      = filepath.Join(goEnv("GOPATH"), "bin", "ginkgo")

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
	CONTROLLER_TOOLS_VERSION = "v0.9.2"
)

// Function to get the current working directory using os.Getwd()
func getWorkingDir() string {
	wd, err := os.Getwd()
	if err != nil {
		fmt.Println("Error getting the current working directory:", err)
		os.Exit(1)
	}
	return wd
}

// All is the default target for building and running tests.
func All() {
	mg.Deps(Build)
}

// Build is the target for building.
func Build() {
	mg.Deps(BuildTrivyOperator)
}

// Target for building trivy-operator binary.
func BuildTrivyOperator() {
	fmt.Println("Building trivy-operator binary...")
	cmd := exec.Command("go", "build", "-o", "./bin/trivy-operator", "./cmd/trivy-operator/main.go")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux")
	err := cmd.Run()
	if err != nil {
		fmt.Println("Error building trivy-operator binary:", err)
		os.Exit(1)
	}
}

// Target for installing Ginkgo CLI.
func GetGinkgo() {
	fmt.Println("Installing Ginkgo CLI...")
	cmd := exec.Command("go", "install", "github.com/onsi/ginkgo/v2/ginkgo")
	err := cmd.Run()
	if err != nil {
		fmt.Println("Error installing Ginkgo CLI:", err)
		os.Exit(1)
	}
}

// Target for installing quicktemplate compiler.
func GetQTC() {
	fmt.Println("Installing quicktemplate compiler...")
	cmd := exec.Command("go", "install", "github.com/valyala/quicktemplate/qtc")
	err := cmd.Run()
	if err != nil {
		fmt.Println("Error installing quicktemplate compiler:", err)
		os.Exit(1)
	}
}

// Target for converting quicktemplate files (*.qtpl) into Go code.
func CompileTemplates() {
	fmt.Println("Converting quicktemplate files to Go code...")
	cmd := exec.Command(filepath.Join(GOBIN, "qtc"))
	err := cmd.Run()
	if err != nil {
		fmt.Println("Error converting quicktemplate files:", err)
		os.Exit(1)
	}
}

// Target for running tests.
func Test() {
	fmt.Println("Running tests...")
	cmd := exec.Command("go", "test", "-v", "-short", "-timeout", "60s", "-coverprofile=coverage.txt", "./...")
	err := cmd.Run()
	if err != nil {
		fmt.Println("Error running tests:", err)
		os.Exit(1)
	}
}

// Target for running integration tests for Trivy Operator.
func ItestsTrivyOperator() {
	fmt.Println("Running integration tests for Trivy Operator...")
	mg.Deps(CheckKubeconfig, GetGinkgo)
	cmd := exec.Command(GINKGO, "-coverprofile=coverage.txt",
		"-coverpkg=github.com/aquasecurity/trivy-operator/pkg/operator,"+
			"github.com/aquasecurity/trivy-operator/pkg/operator/predicate,"+
			"github.com/aquasecurity/trivy-operator/pkg/operator/controller,"+
			"github.com/aquasecurity/trivy-operator/pkg/plugin,"+
			"github.com/aquasecurity/trivy-operator/pkg/plugin/trivy,"+
			"github.com/aquasecurity/trivy-operator/pkg/configauditreport,"+
			"github.com/aquasecurity/trivy-operator/pkg/vulnerabilityreport",
		"./itest/trivy-operator")
	err := cmd.Run()
	if err != nil {
		fmt.Println("Error running integration tests:", err)
		os.Exit(1)
	}
}

// Target for checking if KUBECONFIG environment variable is set.
func CheckKubeconfig() {
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		fmt.Println("Environment variable KUBECONFIG is not set")
		os.Exit(1)
	}
	fmt.Println("KUBECONFIG=", kubeconfig)
}

// Target for removing build artifacts
func Clean() {
	fmt.Println("Removing build artifacts...")
	removeDir(filepath.Join(".", "bin"))
	removeDir(filepath.Join(".", "dist"))
}

// Target for building Docker images for all binaries
func DockerBuild() {
	fmt.Println("Building Docker images for all binaries...")
	DockerBuildTrivyOperator()
	DockerBuildTrivyOperatorUbi8()
}

// Target for building Docker image for trivy-operator
func DockerBuildTrivyOperator() {
	fmt.Println("Building Docker image for trivy-operator...")
	cmd := exec.Command("docker", "build", "--no-cache", "-t", TRIVY_OPERATOR_IMAGE, "-f", "build/trivy-operator/Dockerfile", "bin")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		fmt.Println("Error building Docker image for trivy-operator:", err)
		os.Exit(1)
	}
}

// Target for building Docker image for trivy-operator ubi8
func DockerBuildTrivyOperatorUbi8() {
	fmt.Println("Building Docker image for trivy-operator ubi8...")
	cmd := exec.Command("docker", "build", "--no-cache", "-f", "build/trivy-operator/Dockerfile.ubi8", "-t", TRIVY_OPERATOR_IMAGE_UBI8, "bin")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		fmt.Println("Error building Docker image for trivy-operator ubi8:", err)
		os.Exit(1)
	}
}

// Target for loading Docker images into the KIND cluster
func KindLoadImages() {
	fmt.Println("Loading Docker images into the KIND cluster...")
	mg.Deps(DockerBuildTrivyOperator, DockerBuildTrivyOperatorUbi8)
	cmd := exec.Command(KIND, "load", "docker-image", TRIVY_OPERATOR_IMAGE, TRIVY_OPERATOR_IMAGE_UBI8)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		fmt.Println("Error loading Docker images into the KIND cluster:", err)
		os.Exit(1)
	}
}

// Target for running MkDocs development server to preview the documentation page
func MkDocsServe() {
	fmt.Println("Running MkDocs development server...")
	cmd := exec.Command("docker", "build", "-t", MKDOCS_IMAGE, "-f", "build/mkdocs-material/Dockerfile", "build/trivy-operator")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		fmt.Println("Error building MkDocs image:", err)
		os.Exit(1)
	}

	cmd = exec.Command("docker", "run", "--name", "mkdocs-serve", "--rm", "-v", fmt.Sprintf("%s:/docs", PWD), "-p", fmt.Sprintf("%d:8000", MKDOCS_PORT), MKDOCS_IMAGE)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		fmt.Println("Error running MkDocs development server:", err)
		os.Exit(1)
	}
}

// Target for installing the labeler tool
func InstallLabeler() {
	fmt.Println("Installing the labeler tool...")
	cmd := exec.Command("go", "install", "github.com/knqyf263/labeler@latest")
	cmd.Env = append(os.Environ(), fmt.Sprintf("GOBIN=%s", goEnv("GOBIN")))
	err := cmd.Run()
	if err != nil {
		fmt.Println("Error installing the labeler tool:", err)
		os.Exit(1)
	}
}

// Target for creating the LOCALBIN directory
func LocalBin() {
	fmt.Println("Creating LOCALBIN directory...")
	err := os.MkdirAll(LOCALBIN, os.ModePerm)
	if err != nil {
		fmt.Println("Error creating LOCALBIN directory:", err)
		os.Exit(1)
	}
}

// Target for downloading controller-gen locally if necessary
func ControllerGen() {
	mg.Deps(LocalBin)
	fmt.Println("Downloading controller-gen...")
	cmd := exec.Command("go", "install", "sigs.k8s.io/controller-tools/cmd/controller-gen@"+CONTROLLER_TOOLS_VERSION)
	cmd.Env = append(os.Environ(), "GOBIN="+LOCALBIN)
	err := cmd.Run()
	if err != nil {
		fmt.Println("Error downloading controller-gen:", err)
		os.Exit(1)
	}
}

// Target for downloading envtest-setup locally if necessary
func Envtest() {
	mg.Deps(LocalBin)
	fmt.Println("Downloading envtest-setup...")
	cmd := exec.Command("go", "install", "sigs.k8s.io/controller-runtime/tools/setup-envtest@latest")
	cmd.Env = append(os.Environ(), "GOBIN="+LOCALBIN)
	err := cmd.Run()
	if err != nil {
		fmt.Println("Error downloading envtest-setup:", err)
		os.Exit(1)
	}
}

// Target for verifying generated artifacts
func VerifyGenerated() {
	fmt.Println("Verifying generated artifacts...")
	mg.Deps(GenerateAll)
	cmd := exec.Command("./hack/verify-generated.sh")
	err := cmd.Run()
	if err != nil {
		fmt.Println("Error verifying generated artifacts:", err)
		os.Exit(1)
	}
}

// Target for generating code and manifests
func Generate() {
	fmt.Println("Generating code and manifests...")
	mg.Deps(ControllerGen)
	cmd := exec.Command(CONTROLLER_GEN, "object:headerFile=hack/boilerplate.go.txt", "paths=./pkg/...", "+rbac:roleName=trivy-operator", "output:rbac:artifacts:config=deploy/helm/generated")
	err := cmd.Run()
	if err != nil {
		fmt.Println("Error generating code and manifests:", err)
		os.Exit(1)
	}
}

// Target for generating CRDs and updating static YAML
func Manifests() {
	fmt.Println("Generating CRDs and updating static YAML...")
	mg.Deps(ControllerGen)
	cmd1 := exec.Command(CONTROLLER_GEN, "crd:allowDangerousTypes=true", "paths=./pkg/apis/...", "output:crd:artifacts:config=deploy/helm/crds")
	err1 := cmd1.Run()
	if err1 != nil {
		fmt.Println("Error generating CRDs:", err1)
		os.Exit(1)
	}

	cmd2 := exec.Command("./hack/update-static.yaml.sh")
	err2 := cmd2.Run()
	if err2 != nil {
		fmt.Println("Error updating static YAML:", err2)
		os.Exit(1)
	}
}

// Target for generating all artifacts
func GenerateAll() {
	fmt.Println("Generating all artifacts...")
	mg.Deps(Generate, Manifests)
}

// Target for generating Helm documentation
func GenerateHelmDocs() {
	fmt.Println("Generating Helm documentation...")
	cmd1 := exec.Command("go", "install", "github.com/norwoodj/helm-docs/cmd/helm-docs@latest")
	err1 := cmd1.Run()
	if err1 != nil {
		fmt.Println("Error installing helm-docs:", err1)
		os.Exit(1)
	}

	cmd2 := exec.Command(HELM_DOCS_GEN, "./deploy")
	err2 := cmd2.Run()
	if err2 != nil {
		fmt.Println("Error generating Helm documentation:", err2)
		os.Exit(1)
	}
}

// Target for verifying generated Helm documentation
func VerifyGeneratedHelmDocs() {
	fmt.Println("Verifying generated Helm documentation...")
	mg.Deps(GenerateHelmDocs)
	cmd := exec.Command("./hack/verify-generated.sh")
	err := cmd.Run()
	if err != nil {
		fmt.Println("Error verifying generated Helm documentation:", err)
		os.Exit(1)
	}
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

// getEnvtestKubeAssets returns the path to kubebuilder assets for envtest.
func getEnvtestKubeAssets() string {
	cmd := exec.Command("envtest", "use", ENVTEST_K8S_VERSION, "-p", "path")
	output, err := cmd.Output()
	if err != nil {
		fmt.Println("Error getting envtest kube assets:", err)
		os.Exit(1)
	}
	return string(output)
}

// removeDir removes the directory at the given path.
func removeDir(path string) {
	cmd := exec.Command("rm", "-r", path)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		fmt.Printf("Error removing directory %s: %v\n", path, err)
		os.Exit(1)
	}
}
