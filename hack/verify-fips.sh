#!/usr/bin/env bash
# Verifies the FIPS 140-3 build of trivy-operator:
#   1. the GOFIPS140 module version pinned in .goreleaser.yaml is the same in
#      goreleaser-e2e.yaml, magefile.go and the FIPS docs;
#   2. the given FIPS binary was built with that module version;
#   3. the binary runs in FIPS 140-3 mode by default;
#   4. the binary refuses to start with GODEBUG=fips140=off.
#
# Usage: hack/verify-fips.sh <path to trivy-operator-fips binary>
# The binary must be runnable on the current platform.

set -euo pipefail

if [ $# -ne 1 ]; then
  echo "Usage: $0 <path to trivy-operator-fips binary>" >&2
  exit 2
fi
binary=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")

cd "$(dirname "$0")/.."

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

# run_clean runs the binary with only the given environment variables.
run_clean() {
  if command -v timeout >/dev/null; then
    timeout 30 env -i "$@" "$binary"
  else
    env -i "$@" "$binary"
  fi
}

version=$(grep -oE 'GOFIPS140=v[0-9.]+' .goreleaser.yaml | sort -u)
[ -n "$version" ] || fail ".goreleaser.yaml does not pin GOFIPS140"
[ "$(echo "$version" | wc -l)" -eq 1 ] || fail ".goreleaser.yaml pins several GOFIPS140 versions: $version"
version=${version#GOFIPS140=}
echo "Pinned FIPS 140-3 module: $version"

grep -qE "GOFIPS140=${version}\$" goreleaser-e2e.yaml ||
  fail "goreleaser-e2e.yaml does not pin GOFIPS140=$version"
grep -qE "\"GOFIPS140\": +\"${version}\"" magefile.go ||
  fail "magefile.go does not pin GOFIPS140=$version"
grep -qF "GOFIPS140=${version}\`" docs/getting-started/installation/fips.md ||
  fail "docs/getting-started/installation/fips.md does not mention GOFIPS140=$version"

go version -m "$binary" | grep -qE "^[[:space:]]+build[[:space:]]+GOFIPS140=${version}(-|\$)" ||
  fail "$binary was not built with GOFIPS140=$version"

# The operator exits later on the missing configuration (OPERATOR_NAMESPACE),
# so only its startup output matters here.
out=$(run_clean 2>&1) || true
echo "$out" | grep -qF "\"msg\":\"FIPS 140-3 mode enabled\",\"moduleVersion\":\"${version}\"" ||
  fail "$binary does not run in FIPS 140-3 mode by default. Output:"$'\n'"$out"

if out=$(run_clean GODEBUG=fips140=off 2>&1); then
  fail "$binary started with GODEBUG=fips140=off"
fi
echo "$out" | grep -qF "FIPS 140-3 mode is disabled" ||
  fail "$binary did not refuse to start with GODEBUG=fips140=off. Output:"$'\n'"$out"

echo "OK: $binary"
