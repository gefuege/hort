package vault

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
)

// ErrAlreadyMigrated is the rerun answer of `hort migrate` on a v4 vault (§9.1 step 1).
var ErrAlreadyMigrated = errors.New("already migrated; run `hort kit` to see your Emergency Kit")

// migrateCrash lets tests stop the write sequence after a step, as a crash would.
var migrateCrash func(step string) error

func crashAfter(step string) error {
	if migrateCrash == nil {
		return nil
	}
	return migrateCrash(step)
}

// PreV4BackupPath is the permanent byte copy of the v3 file (§9.1 step 6.1).
func PreV4BackupPath(ref VaultRef) string {
	return ref.Path + ".pre-v4.bak"
}

func checkV3(raw []byte) error {
	if len(raw) >= len(V3Magic) {
		switch string(raw[:len(V3Magic)]) {
		case V3Magic:
			return nil
		case V4Magic:
			return ErrAlreadyMigrated
		case v2Magic:
			return errV2Vault
		}
	}
	return errors.New("not a hort vault")
}

// ReadV3 returns the primary vault file if it is v3 (§9.1 step 1).
func ReadV3(ref VaultRef) ([]byte, error) {
	raw, err := os.ReadFile(ref.Path)
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("no vault found at %s", ref.Path)
	}
	if err != nil {
		return nil, fmt.Errorf("reading vault: %w", err)
	}
	return raw, checkV3(raw)
}

// MigrateV3 converts the v3 vault at ref into a new v4 account with every
// revision unchanged (§9.1 steps 2 to 6.3). checked is the file ReadV3
// returned; the passphrase must open it. The caller saves the session and
// shows the Emergency Kit.
func MigrateV3(ref VaultRef, checked, passphrase []byte, deviceName string) (NewVault, error) {
	return migrateV3(ref, checked, passphrase, deviceName, DefaultArgonParams())
}

func migrateV3(ref VaultRef, checked, passphrase []byte, deviceName string, params ArgonParams) (NewVault, error) {
	key, err := UnlockWithMaterial(checked, passphrase)
	if err != nil {
		return NewVault{}, err
	}
	path, err := canonicalVaultPath(ref.Path)
	if err != nil {
		return NewVault{}, fmt.Errorf("resolving vault path: %w", err)
	}
	ref.Path = path
	unlock, err := lockVault(ref)
	if err != nil {
		return NewVault{}, err
	}
	defer func() { _ = unlock() }()

	// Re-read under the lock: another migrate may have finished meanwhile.
	raw, err := ReadV3(ref)
	if err != nil {
		return NewVault{}, err
	}
	plaintext, err := DecryptWithKey(raw, key)
	if err != nil {
		return NewVault{}, err
	}
	old, err := decodeV3(plaintext)
	if err != nil {
		return NewVault{}, fmt.Errorf("reading v3 vault: %w", err)
	}
	if err := checkEnvelopeSizes(old.Secrets); err != nil {
		return NewVault{}, err
	}

	body, err := NewBody(deviceName)
	if err != nil {
		return NewVault{}, err
	}
	body.Secrets = old.Secrets
	for _, entry := range old.Secrets {
		for _, r := range entry.Revisions {
			body.Sync.Pending = append(body.Sync.Pending, r.ID)
		}
	}
	nv, file, err := sealNewAccount(DefaultServer, body, passphrase, params)
	if err != nil {
		return NewVault{}, err
	}

	if err := writeBackupOnce(PreV4BackupPath(ref), raw); err != nil {
		return NewVault{}, err
	}
	if err := crashAfter("6.1"); err != nil {
		return NewVault{}, err
	}
	if err := writeSecretKeyFile(ref, nv.SecretKey); err != nil {
		return NewVault{}, err
	}
	if err := crashAfter("6.2"); err != nil {
		return NewVault{}, err
	}
	if err := writeFileAtomic(ref.Path, file, 0600); err != nil {
		return NewVault{}, fmt.Errorf("writing vault: %w", err)
	}
	return nv, nil
}

// checkEnvelopeSizes stops the migration before any write when a revision
// cannot travel in one envelope (§9.1 step 4, Revision 2.1 point 3).
func checkEnvelopeSizes(secrets map[string]Entry) error {
	limit := MaxEnvelopeBytes - envelopeOverhead
	var names []string
	for name, entry := range secrets {
		for _, r := range entry.Revisions {
			plain, err := EnvelopePlaintext(name, r)
			if err != nil {
				return err
			}
			if len(plain) > limit {
				names = append(names, fmt.Sprintf("%q", name))
				break
			}
		}
	}
	if len(names) == 0 {
		return nil
	}
	sort.Strings(names)
	return fmt.Errorf("nothing was migrated: these entries hold a revision larger than one sync envelope (%d bytes encoded): %s", limit, strings.Join(names, ", "))
}

// writeBackupOnce creates path exclusively with mode 0600. An existing file
// must already hold exactly data, as after an interrupted migration.
func writeBackupOnce(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if os.IsExist(err) {
		existing, readErr := os.ReadFile(path)
		if readErr != nil {
			return fmt.Errorf("reading existing backup: %w", readErr)
		}
		if !bytes.Equal(existing, data) {
			return fmt.Errorf("%s exists and differs from the v3 vault; move it away and run migrate again", path)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("creating backup: %w", err)
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("writing backup: %w", err)
	}
	return nil
}
