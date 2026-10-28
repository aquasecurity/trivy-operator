//go:build mage

package main

import (
	"reflect"
	"testing"
)

func TestKindImageImportArgs(t *testing.T) {
	want := []string{
		"exec", "--privileged", "-i", "kind-control-plane",
		"ctr", "--namespace=k8s.io", "images", "import",
		"--digests", "--snapshotter=overlayfs", "-",
	}
	if got := kindImageImportArgs("kind-control-plane"); !reflect.DeepEqual(got, want) {
		t.Fatalf("kindImageImportArgs() = %v, want %v", got, want)
	}
}
