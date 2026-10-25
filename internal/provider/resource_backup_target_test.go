package provider

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccBackupTarget(t *testing.T) {
	testAccPreCheck(t)
	cfg := func(secret, extra string) string {
		return fmt.Sprintf(`
resource "hallpass_backup_target" "s3" {
  endpoint          = "https://s3.eu-central-1.amazonaws.com"
  region            = "eu-central-1"
  bucket            = "acme-hallpass-backups"
  prefix            = "prod/"
  access_key_id     = "AKIAEXAMPLE"
  secret_access_key = %q
  interval          = "240m"
  %s
}
`, secret, extra)
	}
	paused := "enabled = false\n  keep_last = 10\n  keep_daily_days = 0"
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg("wJalrXUtnFEMI-example", ""),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("hallpass_backup_target.s3", "id", "backup-target"),
					resource.TestCheckResourceAttr("hallpass_backup_target.s3", "enabled", "true"),
					resource.TestCheckResourceAttr("hallpass_backup_target.s3", "interval", "240m"),
					resource.TestCheckResourceAttr("hallpass_backup_target.s3", "keep_last", "48"),
					resource.TestCheckResourceAttr("hallpass_backup_target.s3", "keep_daily_days", "30"),
					resource.TestCheckResourceAttr("hallpass_backup_target.s3", "path_style", "false"),
				),
			},
			{
				Config: cfg("wJalrXUtnFEMI-example", paused),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("hallpass_backup_target.s3", "enabled", "false"),
					resource.TestCheckResourceAttr("hallpass_backup_target.s3", "keep_last", "10"),
					resource.TestCheckResourceAttr("hallpass_backup_target.s3", "keep_daily_days", "0"),
				),
			},
			{
				ResourceName:      "hallpass_backup_target.s3",
				ImportState:       true,
				ImportStateId:     "backup-target",
				ImportStateVerify: true,
				// The secret is write-only; an imported interval reads back as "4h" (same duration).
				ImportStateVerifyIgnore: []string{"secret_access_key", "interval"},
			},
			{
				Config: cfg("wJalrXUtnFEMI-rotated", paused),
				Check:  resource.TestCheckResourceAttr("hallpass_backup_target.s3", "secret_access_key", "wJalrXUtnFEMI-rotated"),
			},
		},
	})
}
