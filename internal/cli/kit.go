package cli

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/gefuege/hort/internal/vault"
	"golang.org/x/term"
)

// FormatKit renders the Emergency Kit (contract §2.7). The passphrase is
// never printed.
func FormatKit(server string, accountID, secretKey []byte) string {
	return fmt.Sprintf(`
HORT EMERGENCY KIT

Use this kit with your passphrase to open your Hort vault on a new device or at the server below, and enter it nowhere else.

Server:      %s
Account ID:  %s
Secret Key:  %s
Passphrase:  ______________________________

`, server, vault.FormatAccountID(accountID), vault.FormatSecretKey(secretKey))
}

// lastGroup is the last five-symbol data group of the displayed Secret Key.
func lastGroup(secretKey []byte) string {
	groups := strings.Split(vault.FormatSecretKey(secretKey), "-")
	return groups[len(groups)-2]
}

// confirmKit prints the kit to stderr. On a terminal it returns only after the
// user typed the last group of the Secret Key back. Without a terminal on
// stdin, as in scripts and with HORT_PASSPHRASE, nobody can type it back: the
// kit is printed and the confirmation is skipped with a note.
func confirmKit(server string, accountID, secretKey []byte) error {
	fmt.Fprint(os.Stderr, FormatKit(server, accountID, secretKey))
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprintln(os.Stderr, "No terminal to confirm the Emergency Kit; save it now, `hort kit` shows it again.")
		return nil
	}
	return confirmLastGroup(os.Stdin, secretKey)
}

func confirmLastGroup(in io.Reader, secretKey []byte) error {
	want := lastGroup(secretKey)
	lines := bufio.NewScanner(in)
	for {
		fmt.Fprint(os.Stderr, "Save the kit, then type the last group of your Secret Key (before the final symbol): ")
		if !lines.Scan() {
			fmt.Fprintln(os.Stderr)
			return fmt.Errorf("the Emergency Kit was not confirmed; run `hort kit` to see it again")
		}
		if vault.NormalizeCrockford(lines.Text()) == want {
			fmt.Fprintln(os.Stderr, "Emergency Kit confirmed.")
			return nil
		}
		fmt.Fprintln(os.Stderr, "That does not match; look at the Secret Key line again.")
	}
}
