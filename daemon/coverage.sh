#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"

# Exclude by the generated-code marker, not a hardcoded path - this
# stays correct if generated code shows up anywhere else later.
covpkgs=$(
  for pkg in $(go list ./...); do
    dir=$(go list -f '{{.Dir}}' "$pkg")
    if ! grep -qrl "^// Code generated" "$dir"/*.go 2>/dev/null; then
      echo "$pkg"
    fi
  done | paste -sd, -
)

go test ./... -coverpkg="$covpkgs" -coverprofile=coverage.out
go tool cover -func=coverage.out | tail -1
go tool cover -html=coverage.out -o coverage.html
echo "Full report: coverage.html"
