package cli

import (
	"context"
	"os"
	"os/signal"

	"github.com/gefuege/hort/internal/mcp"
	"github.com/gefuege/hort/internal/vault"
)

// CmdMCP serves the request_secret tool on stdin and stdout (contract §7).
func CmdMCP(version string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	return mcp.Serve(ctx, mcp.Deps{Sync: func(ref vault.VaultRef, vk []byte) error {
		_, err := syncVault(ref, vk)
		return err
	}, Version: version})
}
