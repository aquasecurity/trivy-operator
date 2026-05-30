package trivy

// This file is only compiled during `go test` and re-exports a
// handful of unexported helpers so external test packages
// (trivy_test) can exercise them directly.

// ScanWrapperInstallContainerForTest exposes scanWrapperInstallContainer
// for use by tests in the trivy_test package.
var ScanWrapperInstallContainerForTest = scanWrapperInstallContainer
