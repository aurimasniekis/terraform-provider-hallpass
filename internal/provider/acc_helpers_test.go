package provider

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"golang.org/x/crypto/ssh"

	"github.com/aurimasniekis/terraform-provider-hallpass/internal/client"
)

// randName returns a fresh alias-safe name (lowercase letter first).
func randName(prefix string) string {
	return prefix + "-" + acctest.RandStringFromCharSet(8, "abcdefghijklmnopqrstuvwxyz0123456789")
}

// newPublicKey generates an Ed25519 public key in authorized_keys format.
func newPublicKey(t *testing.T, comment string) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k))) + " " + comment
}

// capture stores an attribute of a resource in *dst (for out-of-band drift steps).
func capture(name, attr string, dst *string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[name]
		if !ok {
			return fmt.Errorf("%s not in state", name)
		}
		*dst = rs.Primary.Attributes[attr]
		if *dst == "" {
			return fmt.Errorf("%s.%s is empty", name, attr)
		}
		return nil
	}
}

// importID builds "<a>/<b>"-style import IDs from state attributes.
func importID(name string, attrs ...string) resource.ImportStateIdFunc {
	return func(s *terraform.State) (string, error) {
		rs, ok := s.RootModule().Resources[name]
		if !ok {
			return "", fmt.Errorf("%s not in state", name)
		}
		parts := make([]string, 0, len(attrs))
		for _, a := range attrs {
			parts = append(parts, rs.Primary.Attributes[a])
		}
		return strings.Join(parts, "/"), nil
	}
}

func expectUpdate(name string) resource.ConfigPlanChecks {
	return resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(name, plancheck.ResourceActionUpdate)}}
}

func expectReplace(name string) resource.ConfigPlanChecks {
	return resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(name, plancheck.ResourceActionReplace)}}
}

func expectRecreate(name string) resource.ConfigPlanChecks {
	return resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(name, plancheck.ResourceActionCreate)}}
}

// oob runs an out-of-band API call and fails the test on error.
func oob(t *testing.T, f func(ctx context.Context, c *client.Client) error) func() {
	return func() {
		t.Helper()
		if err := f(context.Background(), apiClient(t)); err != nil {
			t.Fatalf("out-of-band change: %v", err)
		}
	}
}

// checkGone verifies that every resource of the given type is gone from HallPass.
func checkGone(t *testing.T, typ string, get func(ctx context.Context, c *client.Client, attrs map[string]string) error) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		c := apiClient(t)
		for _, rs := range s.RootModule().Resources {
			if rs.Type != typ {
				continue
			}
			err := get(context.Background(), c, rs.Primary.Attributes)
			if err == nil {
				return fmt.Errorf("%s %s still exists", typ, rs.Primary.ID)
			}
			if !client.IsNotFound(err) {
				return fmt.Errorf("%s %s: %w", typ, rs.Primary.ID, err)
			}
		}
		return nil
	}
}

func idRE(prefix string) *regexp.Regexp { return regexp.MustCompile(`^` + prefix + `_[0-9a-z]+$`) }
