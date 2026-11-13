package cli

import (
	"bufio"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/gefuege/hort/internal/api"
	"github.com/gefuege/hort/internal/store"
	"github.com/gefuege/hort/internal/vault"
	"golang.org/x/term"
)

// CmdTake saves a secret shared by link as default values under its shared
// name or as, then deletes the share. Values never reach stdout or stderr.
func CmdTake(link, as string) error {
	ref, key := requireKey()
	origin, id, linkKey, err := vault.ParseShareLink(link)
	if err != nil {
		return err
	}
	name, err := readRecipientName()
	if err != nil {
		return err
	}
	keys, err := vault.DeriveShareKeys(name, linkKey, id)
	if err != nil {
		return err
	}
	ct, err := api.OpenShare(origin, id, keys.Token)
	var wrong *api.WrongShareToken
	var apiErr *api.Error
	switch {
	case errors.As(err, &wrong):
		return fmt.Errorf("that name does not open this link; %d tries left", wrong.TriesLeft)
	case errors.As(err, &apiErr) && apiErr.Status == http.StatusNotFound:
		return errors.New("this link no longer opens; ask the sender for a new one")
	case err != nil:
		return err
	}
	shared, err := vault.OpenShare(keys.Enc, id, ct)
	if err != nil {
		return err
	}
	if shared.Kind == vault.ShareKindRequest {
		return errors.New("this link asks you for values; open it in a browser to answer")
	}
	if as == "" {
		as = shared.Name
	}
	// Sync first, as reads do, so the name check sees secrets of other devices.
	autoSync(ref, key)
	err = store.New(ref, key).SaveShared(as, shared.Description, shared.Fields)
	if errors.Is(err, store.ErrNameTaken) {
		return fmt.Errorf("a secret named %q exists; take it under another name with --as NAME", as)
	}
	if err != nil {
		return err
	}
	saved := fmt.Sprintf("Saved %s (%d fields).", as, len(shared.Fields))
	if len(shared.Fields) == 1 {
		saved = fmt.Sprintf("Saved %s (1 field).", as)
	}
	if err := api.DeleteShare(origin, id, keys.Token); err != nil {
		fmt.Fprintln(os.Stderr, saved)
		fmt.Fprintf(os.Stderr, "warning: the shared link stays open until it expires (%v)\n", err)
	} else {
		fmt.Fprintln(os.Stderr, saved+" The shared link is deleted.")
	}
	autoSync(ref, key)
	return nil
}

// readRecipientName asks "Who are you? " on a terminal; otherwise it reads
// one line from stdin.
func readRecipientName() (string, error) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprint(os.Stderr, "Who are you? ")
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return "", errors.New("no name given")
	}
	return strings.TrimRight(line, "\r\n"), nil
}
