package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/gefuege/hort/internal/helptext"
	"github.com/gefuege/hort/internal/vault"
)

// CmdMigrate converts the v3 vault into a new v4 account once (§9.1).
func CmdMigrate() error {
	ref, err := vault.PrimaryRef()
	if err != nil {
		return err
	}
	raw, err := vault.ReadV3(ref)
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, helptext.ConvergeFirst)
	pass, err := ReadPassphrase("Enter passphrase: ")
	if err != nil {
		return err
	}
	created, err := vault.MigrateV3(ref, raw, pass, defaultDeviceName())
	if err != nil {
		return err
	}
	if err := vault.SaveSessionFor(ref, created.VK); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Vault migrated to v4 and unlocked. The v3 file stays in %s.\n", vault.PreV4BackupPath(ref))
	if dir, err := vault.HortDir(); err == nil {
		if _, err := os.Stat(filepath.Join(dir, "sources")); err == nil {
			fmt.Fprintf(os.Stderr, "%s is left untouched and no longer read.\n", filepath.Join(dir, "sources"))
		}
	}
	if err := confirmKit(created.Server, created.AccountID, created.SecretKey); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Run `hort sync` to register this vault on %s.\n", created.Server)
	return nil
}
