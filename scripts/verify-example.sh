#!/usr/bin/env bash
# Applies examples/complete against a throwaway HallPass started by the acceptance harness (TestMain), checks that a
# second plan is empty, then destroys it. Needs bin/hallpass (make hallpass-bin) and terraform.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
go build -o bin/terraform-provider-hallpass .
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cat >"$work/terraformrc" <<RC
provider_installation {
  dev_overrides {
    "aurimasniekis/hallpass" = "$root/bin"
  }
  direct {}
}
RC
export TF_CLI_CONFIG_FILE="$work/terraformrc" TF_IN_AUTOMATION=1
cp examples/complete/main.tf "$work/"
TF_ACC=1 HALLPASS_EXAMPLE_DIR="$work" go test ./internal/provider/ -run TestExampleComplete -count=1 -v -timeout 10m
