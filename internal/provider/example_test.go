package provider

import (
	"errors"
	"os"
	"os/exec"
	"testing"
)

// TestExampleComplete applies examples/complete with the real Terraform CLI against the harness's HallPass (via
// scripts/verify-example.sh, which builds the provider and sets up dev_overrides), checks that a second plan is
// empty, and destroys it.
func TestExampleComplete(t *testing.T) {
	dir := os.Getenv("HALLPASS_EXAMPLE_DIR")
	if dir == "" {
		t.Skip("run through scripts/verify-example.sh")
	}
	testAccPreCheck(t)
	tf := os.Getenv("TF_ACC_TERRAFORM_PATH")
	run := func(args ...string) error {
		cmd := exec.Command(tf, args...) //nolint:gosec // test
		cmd.Dir, cmd.Stdout, cmd.Stderr = dir, os.Stdout, os.Stderr
		return cmd.Run()
	}
	if err := run("apply", "-auto-approve", "-input=false"); err != nil {
		t.Fatalf("apply: %v", err)
	}
	err := run("plan", "-detailed-exitcode", "-input=false")
	var ee *exec.ExitError
	if errors.As(err, &ee) && ee.ExitCode() == 2 {
		t.Error("second plan is not empty")
	} else if err != nil {
		t.Errorf("plan: %v", err)
	}
	if err := run("destroy", "-auto-approve", "-input=false"); err != nil {
		t.Fatalf("destroy: %v", err)
	}
}
