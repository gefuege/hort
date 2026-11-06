package cli

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/gefuege/hort/internal/store"
	"github.com/gefuege/hort/internal/vault"
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

// readSecretKey parses HORT_SECRET_KEY, or else ~/.hort/secret-key. A bad
// check symbol fails here, before any Argon2id work.
func readSecretKey(ref vault.VaultRef) ([]byte, error) {
	text := os.Getenv("HORT_SECRET_KEY")
	if text == "" {
		var err error
		if text, err = vault.ReadSecretKeyFile(ref); err != nil {
			return nil, err
		}
	}
	return vault.ParseSecretKey(strings.TrimSpace(text))
}

// readNewPassphrase asks twice unless HORT_PASSPHRASE answers both prompts.
func readNewPassphrase() ([]byte, error) {
	pass, err := ReadPassphrase("Enter new passphrase: ")
	if err != nil {
		return nil, err
	}
	confirm, err := ReadPassphrase("Confirm passphrase: ")
	if err != nil {
		return nil, err
	}
	if string(pass) != string(confirm) {
		return nil, fmt.Errorf("passphrases do not match")
	}
	return pass, nil
}

// defaultDeviceName is <os>-<4 random chars>; the hostname would leak (§5.2).
func defaultDeviceName() string {
	const alphabet = "0123456789abcdefghjkmnpqrstvwxyz"
	b := make([]byte, 4)
	_, _ = rand.Read(b) // crypto/rand.Read never fails
	for i := range b {
		b[i] = alphabet[b[i]&31]
	}
	return runtime.GOOS + "-" + string(b)
}

// CmdInit creates a new v4 vault. Registering the account on the server
// comes with `hort sync`; this command makes no network call.
func CmdInit(server, name string) error {
	ref, err := vault.PrimaryRef()
	if err != nil {
		return err
	}
	exists, err := vault.RefExists(ref)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("a vault already exists at %s", ref.Path)
	}
	if server == "" {
		server = vault.DefaultServer
	}
	if name == "" {
		name = defaultDeviceName()
	}
	pass, err := readNewPassphrase()
	if err != nil {
		return err
	}
	created, err := vault.CreateVault(ref, server, name, pass)
	if err != nil {
		return err
	}
	if err := vault.SaveSessionFor(ref, created.VK); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Vault created and unlocked.")
	return confirmKit(created.Server, created.AccountID, created.SecretKey)
}

// CmdUnlock unwraps VK with the passphrase and the Secret Key.
func CmdUnlock() error {
	ref, err := vault.PrimaryRef()
	if err != nil {
		return err
	}
	exists, err := vault.RefExists(ref)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("no vault found — run `hort init` first")
	}

	if vault.IsUnlockedFor(ref) {
		fmt.Fprintln(os.Stderr, "Vault is already unlocked.")
		return nil
	}
	if _, err := vault.ReadInfo(ref); err != nil {
		return err
	}
	secretKey, err := readSecretKey(ref)
	if err != nil {
		return err
	}
	pass, err := ReadPassphrase("Enter passphrase: ")
	if err != nil {
		return err
	}
	vk, err := vault.UnlockVault(ref, pass, secretKey)
	if err != nil {
		return err
	}
	if err := vault.SaveSessionFor(ref, vk); err != nil {
		return err
	}

	fmt.Fprintln(os.Stderr, "Vault unlocked.")
	return nil
}

// CmdLock locks the vault by clearing its session.
func CmdLock() error {
	ref, err := vault.PrimaryRef()
	if err != nil {
		return err
	}
	if err := vault.ClearSessionFor(ref); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Vault locked.")
	return nil
}

// CmdStatus reports the local vault without any network call. Apps that
// depend on Hort can use `hort status --json` as their single readiness check.
func CmdStatus(jsonOutput bool) error {
	ref, err := vault.PrimaryRef()
	if err != nil {
		return err
	}
	var st Status
	exists, err := vault.RefExists(ref)
	if err != nil {
		return err
	}
	if exists {
		info, err := vault.ReadInfo(ref)
		if err != nil {
			return err
		}
		st.AccountID, st.Server = vault.FormatAccountID(info.AccountID), info.Server
		st.Unlocked = vault.IsUnlockedFor(ref)
	}
	if st.Unlocked {
		key, err := vault.LoadSessionFor(ref)
		var data *vault.VaultData
		if err == nil {
			data, _, err = vault.LoadVault(ref, key)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: session does not open the vault: %v\n", err)
		} else {
			count := 0
			for _, entry := range data.Secrets {
				if _, _, visible := entry.Current(); visible {
					count++
				}
			}
			st.Ready = true
			st.Registered, st.DeviceID, st.SecretCount = &data.Sync.Registered, data.Device.ID, &count
		}
	}
	fmt.Print(FormatStatus(st, jsonOutput))
	return nil
}

// requireKey returns ref and VK; a locked vault exits with 2.
func requireKey() (vault.VaultRef, []byte) {
	ref, err := vault.PrimaryRef()
	if err == nil {
		var key []byte
		if key, err = vault.LoadSessionFor(ref); err == nil {
			return ref, key
		}
	}
	fmt.Fprintln(os.Stderr, err)
	os.Exit(ExitLocked)
	return vault.VaultRef{}, nil
}

// requireStore loads the store. If the vault is locked we exit with 2.
func requireStore() *store.Store {
	return store.New(requireKey())
}

// CmdKit prints the Emergency Kit again; it needs an unlocked vault.
func CmdKit() error {
	ref, key := requireKey()
	if _, _, err := vault.LoadVault(ref, key); err != nil {
		return err
	}
	info, err := vault.ReadInfo(ref)
	if err != nil {
		return err
	}
	secretKey, err := readSecretKey(ref)
	if err != nil {
		return err
	}
	fmt.Fprint(os.Stderr, FormatKit(info.Server, info.AccountID, secretKey))
	return nil
}

// CmdPassphrase sets a new passphrase with the same Secret Key.
func CmdPassphrase() error {
	ref, key := requireKey()
	secretKey, err := readSecretKey(ref)
	if err != nil {
		return err
	}
	pass, err := readNewPassphrase()
	if err != nil {
		return err
	}
	if err := vault.ChangePassphrase(ref, key, pass, secretKey); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Passphrase changed.")
	return nil
}

// CmdGetSecret retrieves a secret.
func CmdGetSecret(name, env, context string) error {
	val, err := requireStore().GetSecret(name, env, context)
	if err != nil {
		return err
	}
	fmt.Print(val)
	return nil
}

// CmdSetSecret stores a secret.
func CmdSetSecret(name, value, env, context, description string) error {
	if err := requireStore().SetSecret(name, value, env, context, description); err != nil {
		return err
	}
	announceStored("secret", name, env, context)
	return nil
}

// CmdList lists all entries.
func CmdList(jsonOutput bool) error {
	entries, err := requireStore().List()
	if err != nil {
		return err
	}
	fmt.Print(FormatList(entries, jsonOutput))
	return nil
}

// CmdDescribe shows entry details.
func CmdDescribe(name string, jsonOutput bool) error {
	entry, err := requireStore().Describe(name)
	if err != nil {
		return err
	}
	fmt.Print(FormatDescribe(entry, jsonOutput))
	return nil
}

// CmdDelete removes an entry or specific env/context combination.
func CmdDelete(name, env, context string) error {
	if err := requireStore().Delete(name, env, context); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Deleted.")
	return nil
}

// CmdHistory exposes values only through an explicitly requested history read.
func CmdHistory(name string, jsonOutput bool) error {
	history, err := requireStore().History(name)
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
	for _, r := range history.Revisions {
		at := "unknown"
		if r.RecordedAt != nil {
			at = r.RecordedAt.UTC().Format(time.RFC3339Nano)
		}
		fmt.Printf("%s %s %s %q %q\n", at, r.ID, r.Op, r.Key, r.Value)
	}
	return nil
}
