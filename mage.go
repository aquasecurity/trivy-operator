//go:build ignore

package main

import (
	"os"

	"github.com/magefile/mage/mage"
)

// This file allows someone to run mage commands without mage installed
// by running `go run mage.go TARGET`.
// See https://magefile.org/zeroinstall/
func main() { os.Exit(mage.Main()) }
