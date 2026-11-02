package cli

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/s16e/hort/internal/store"
	"github.com/s16e/hort/internal/vault"
	"golang.org/x/term"
)

// ExitLocked is the exit code when the vault is locked.
const ExitLocked = 2

// ReadPassphrase reads a passphrase from HORT_PASSPHRASE env var or terminal (no echo).
func ReadPassphrase(prompt string) ([]byte, error) {
	if env := os.Getenv("HORT_PASSPHRASE"); env != "" {
		return []byte(env), nil
	}

	fmt.Fprint(os.Stderr, prompt)
	pass, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, fmt.Errorf("reading passphrase: %w", err)
	}
	return pass, nil
}

// CmdInit creates a new primary vault or restores from an existing passphrase.
func CmdInit(restore bool) error {
	exists, err := vault.VaultExists()
	if err != nil {
		return err
	}

	if exists && !restore {
		return fmt.Errorf("vault already exists — use `hort init --restore` to restore with existing passphrase")
	}

	if restore && !exists {
		return fmt.Errorf("no vault found — place the existing vault at ~/.hort/vault.enc before running `hort init --restore`")
	}

	pass, err := ReadPassphrase("Enter passphrase: ")
	if err != nil {
		return err
	}

	ref, err := vault.PrimaryRef()
	if err != nil {
		return err
	}

	if !restore {
		confirm, err := ReadPassphrase("Confirm passphrase: ")
		if err != nil {
			return err
		}
		if string(pass) != string(confirm) {
			return fmt.Errorf("passphrases do not match")
		}
	}

	if restore {
		key, err := vault.UnlockVault(ref, pass)
		if err != nil {
			return err
		}
		if err := vault.SaveSessionFor(ref, key); err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "Vault restored and unlocked.")
		return nil
	}

	key, err := vault.CreatePrimaryVault(pass)
	if err != nil {
		return err
	}
	if err := vault.SaveSessionFor(ref, key); err != nil {
		return err
	}

	fmt.Fprintln(os.Stderr, "Vault created and unlocked.")
	return nil
}

// CmdUnlock unlocks the primary vault.
func CmdUnlock() error {
	exists, err := vault.VaultExists()
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("no vault found — run `hort init` first")
	}

	if vault.IsUnlocked() {
		fmt.Fprintln(os.Stderr, "Vault is already unlocked.")
		return nil
	}

	pass, err := ReadPassphrase("Enter passphrase: ")
	if err != nil {
		return err
	}

	ref, err := vault.PrimaryRef()
	if err != nil {
		return err
	}

	key, err := vault.UnlockVault(ref, pass)
	if err != nil {
		return err
	}

	if err := vault.SaveSessionFor(ref, key); err != nil {
		return err
	}

	fmt.Fprintln(os.Stderr, "Vault unlocked.")
	return nil
}

// CmdLock locks the primary vault. Mounted sources remain untouched.
func CmdLock() error {
	if err := vault.ClearSession(); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Vault locked.")
	return nil
}

// CmdStatus shows primary vault status in a single call. Apps that depend
// on Hort can use `hort status --json` as their single readiness check.
func CmdStatus(jsonOutput bool) error {
	primaryUnlocked := vault.IsUnlocked()
	path, _ := vault.VaultPath()

	secretCount := 0

	if primaryUnlocked {
		s, err := store.NewFromSession()
		if err == nil {
			entries, err := s.List()
			if err == nil {
				for _, e := range entries {
					if e.Source != vault.PrimarySourceName {
						continue
					}
					secretCount++
				}
			}
		}
	}

	fmt.Print(FormatStatus(primaryUnlocked, path, secretCount, jsonOutput))
	return nil
}

// requireStore loads a merged store. If the primary is locked we exit with 2.
func requireStore() *store.Store {
	s, err := store.NewFromSession()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(ExitLocked)
	}
	return s
}

// CmdGetSecret retrieves a secret from the merged view.
func CmdGetSecret(name, env, context, source string) error {
	s := requireStore()
	var val string
	var err error
	if source != "" {
		val, err = s.GetFrom(source, name, env, context)
	} else {
		val, _, err = s.GetSecret(name, env, context)
	}
	if err != nil {
		return err
	}
	fmt.Print(val)
	return nil
}

// CmdSetSecret stores a secret. Targets the source named via --source, or
// primary if none specified.
func CmdSetSecret(name, value, env, context, description, source string) error {
	s := requireStore()
	if err := s.SetSecret(source, name, value, env, context, description); err != nil {
		return err
	}
	announceStored("secret", name, env, context, source)
	return nil
}

// CmdList lists entries across all unlocked sources.
func CmdList(jsonOutput bool) error {
	s := requireStore()
	entries, err := s.List()
	if err != nil {
		return err
	}
	fmt.Print(FormatList(entries, jsonOutput))
	return nil
}

// CmdDescribe shows entry details across sources.
func CmdDescribe(name string, jsonOutput bool) error {
	s := requireStore()
	entries, err := s.Describe(name)
	if err != nil {
		return err
	}
	fmt.Print(FormatDescribe(entries, jsonOutput))
	return nil
}

// CmdDelete removes an entry or specific env/context combination.
func CmdDelete(name, env, context, source string) error {
	s := requireStore()
	if err := s.Delete(source, name, env, context); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Deleted.")
	return nil
}

// CmdSourceMount registers a mounted source.
// keyHex must be a 64-char (32-byte) hex string.
func CmdSourceMount(name, path, keyHex, kdfFlag string) error {
	if path == "" {
		return fmt.Errorf("--path is required")
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolving path: %w", err)
	}

	rawKey, err := hex.DecodeString(keyHex)
	if err != nil {
		return fmt.Errorf("--key-hex must be valid hex: %w", err)
	}
	if len(rawKey) != vault.KeySize {
		return fmt.Errorf("--key-hex must decode to %d bytes, got %d", vault.KeySize, len(rawKey))
	}

	kdf := vault.KDFRawKey
	switch kdfFlag {
	case "", "raw":
		kdf = vault.KDFRawKey
	case "argon2", "argon2id":
		kdf = vault.KDFArgon2id
	default:
		return fmt.Errorf("--kdf must be 'raw' or 'argon2id' (got %q)", kdfFlag)
	}

	ref, err := vault.MountedRefAt(name, absPath)
	if err != nil {
		return err
	}

	exists, err := vault.RefExists(ref)
	if err != nil {
		return err
	}
	var sessionKey []byte
	if exists {
		sessionKey, err = vault.UnlockVault(ref, rawKey)
		if err != nil {
			return fmt.Errorf("mount %s: %w", name, err)
		}
	} else {
		sessionKey, err = vault.CreateVault(ref, rawKey, kdf)
		if err != nil {
			return fmt.Errorf("creating mount %s: %w", name, err)
		}
	}

	if err := vault.SaveSessionFor(ref, sessionKey); err != nil {
		return err
	}

	record := vault.SourceRecord{
		Name: name,
		Path: absPath,
		KDF:  kdf,
	}
	if err := vault.AddSource(record); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "Source %q mounted at %s.\n", name, absPath)
	return nil
}

// CmdSourceUnmount clears the session for a mount and removes it from the registry.
// The vault file itself stays on disk.
func CmdSourceUnmount(name string) error {
	records, err := vault.ListSources()
	if err != nil {
		return err
	}
	var rec *vault.SourceRecord
	for i := range records {
		if records[i].Name == name {
			rec = &records[i]
			break
		}
	}
	if rec == nil {
		return fmt.Errorf("source %q is not mounted", name)
	}
	ref, err := vault.RefFromRecord(*rec)
	if err != nil {
		return err
	}
	if err := vault.ClearSessionFor(ref); err != nil {
		return err
	}
	if err := vault.RemoveSource(name); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Source %q unmounted.\n", name)
	return nil
}

// CmdSourceList renders all known sources (primary + registered mounts).
func CmdSourceList(jsonOutput bool) error {
	primaryRef, err := vault.PrimaryRef()
	if err != nil {
		return err
	}
	items := []SourceStatus{{
		Name:     primaryRef.Name,
		Path:     primaryRef.Path,
		KDF:      "argon2id",
		Unlocked: vault.IsUnlockedFor(primaryRef),
		Primary:  true,
	}}

	records, err := vault.ListSources()
	if err != nil {
		return err
	}
	for _, rec := range records {
		ref, err := vault.RefFromRecord(rec)
		if err != nil {
			continue
		}
		items = append(items, SourceStatus{
			Name:     rec.Name,
			Path:     rec.Path,
			KDF:      kdfLabel(rec.KDF),
			Unlocked: vault.IsUnlockedFor(ref),
		})
	}

	fmt.Print(FormatSourceList(items, jsonOutput))
	return nil
}

func kdfLabel(m vault.KDFMode) string {
	switch m {
	case vault.KDFRawKey:
		return "raw"
	case vault.KDFArgon2id:
		return "argon2id"
	default:
		return "unknown"
	}
}

// CmdHistory exposes values only through an explicitly requested history read.
func CmdHistory(name, source string, jsonOutput bool) error {
	history, err := requireStore().History(source, name)
	if err != nil {
		return err
	}
	if jsonOutput {
		encoded, err := json.MarshalIndent(history, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(encoded))
		return nil
	}
	fmt.Printf("Source: %s\n", history.Source)
	for _, r := range history.Revisions {
		at := "unknown"
		if r.RecordedAt != nil {
			at = r.RecordedAt.UTC().Format(time.RFC3339Nano)
		}
		fmt.Printf("%s %s %s %q %q\n", at, r.ID, r.Op, r.Key, r.Value)
	}
	return nil
}

// CmdMigrate operates on one unlocked source without changing its session.
func CmdMigrate(source string) error {
	ref, err := vault.PrimaryRef()
	if err != nil {
		return err
	}
	if source != "" && source != vault.PrimarySourceName {
		records, err := vault.ListSources()
		if err != nil {
			return err
		}
		found := false
		for _, record := range records {
			if record.Name == source {
				ref, err = vault.RefFromRecord(record)
				if err != nil {
					return err
				}
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("source %q is not mounted", source)
		}
	}
	key, err := vault.LoadSessionFor(ref)
	if err != nil {
		return err
	}
	if err := vault.MigrateVault(ref, key); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Vault migrated to v3; encrypted pre-v3 backup retained.")
	return nil
}
