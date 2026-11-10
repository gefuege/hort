package cli

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/gefuege/hort/internal/api"
	"github.com/gefuege/hort/internal/vault"
)

// adminServer resolves the server and the operator secret of `hort invite`;
// it needs no vault. The secret is sent only over https.
func adminServer(server string) (string, string, error) {
	if server == "" {
		server = vault.DefaultServer
	}
	if err := vault.CheckServerURL(server); err != nil {
		return "", "", err
	}
	token := os.Getenv("HORT_ADMIN_TOKEN")
	if token == "" {
		return "", "", errors.New("HORT_ADMIN_TOKEN is not set; it holds the server's ADMIN_TOKEN secret")
	}
	return server, token, nil
}

// CmdInviteCreate creates a single-use invitation and prints its invite link,
// which carries the code in the fragment.
func CmdInviteCreate(server string) error {
	server, token, err := adminServer(server)
	if err != nil {
		return err
	}
	id, code, err := api.CreateInvitation(server, token)
	if err != nil {
		return err
	}
	fmt.Println(strings.TrimRight(server, "/") + "/invite#" + code)
	fmt.Fprintf(os.Stderr, "Invitation %s created; the link works once.\n", id)
	return nil
}

// CmdInviteList prints every invitation: ID, creation time, open or used, and
// the account that used it.
func CmdInviteList(server string) error {
	server, token, err := adminServer(server)
	if err != nil {
		return err
	}
	list, err := api.ListInvitations(server, token)
	if err != nil {
		return err
	}
	stamp := func(t int64) string { return time.Unix(t, 0).UTC().Format(time.RFC3339) }
	for _, inv := range list {
		line := fmt.Sprintf("%s  created %s  open", inv.ID, stamp(inv.CreatedAt))
		if inv.UsedAt != nil {
			account := ""
			if inv.AccountID != nil {
				account = *inv.AccountID
			}
			line = fmt.Sprintf("%s  created %s  used %s by %s", inv.ID, stamp(inv.CreatedAt), stamp(*inv.UsedAt), account)
		}
		fmt.Println(line)
	}
	return nil
}

// CmdInviteRevoke deletes an open invitation; its link stops working.
func CmdInviteRevoke(server, id string) error {
	server, token, err := adminServer(server)
	if err != nil {
		return err
	}
	if err := api.RevokeInvitation(server, token, id); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Invitation %s revoked.\n", id)
	return nil
}
