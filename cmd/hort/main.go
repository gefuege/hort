package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/s16e/hort/internal/cli"
	"github.com/s16e/hort/internal/helptext"
	"github.com/spf13/cobra"
)

func main() {
	var (
		flagSecret     string
		flagSetSecret  string
		flagEnv        string
		flagContext    string
		flagValue      string
		flagValueStdin bool
		flagDesc       string
		flagList       bool
		flagDescribe   string
		flagDelete     string
		flagJSON       bool
		flagSource     string
	)

	root := &cobra.Command{
		Use:   "hort",
		Short: "Hort — Local secret store for humans and AI agents",
		Long:  helptext.HelpText,
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				return cli.CmdSearch(strings.Join(args, " "), flagJSON)
			}
			if flagSecret != "" {
				return cli.CmdGetSecret(flagSecret, flagEnv, flagContext, flagSource)
			}
			if flagSetSecret != "" {
				value, err := writeValue(flagValue, flagValueStdin, cmd.InOrStdin())
				if err != nil {
					return fmt.Errorf("set secret: %w", err)
				}
				return cli.CmdSetSecret(flagSetSecret, value, flagEnv, flagContext, flagDesc, flagSource)
			}
			if flagList {
				return cli.CmdList(flagJSON)
			}
			if flagDescribe != "" {
				return cli.CmdDescribe(flagDescribe, flagJSON)
			}
			if flagDelete != "" {
				return cli.CmdDelete(flagDelete, flagEnv, flagContext, flagSource)
			}
			return cmd.Help()
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	// Read flags
	root.Flags().StringVarP(&flagSecret, "secret", "g", "", "Get a secret value")

	// Write flags
	root.Flags().StringVarP(&flagSetSecret, "set-secret", "s", "", "Store a secret")
	root.Flags().StringVarP(&flagValue, "value", "v", "", "Value to store")
	root.Flags().BoolVar(&flagValueStdin, "value-stdin", false, "Read the value to store from stdin")
	root.Flags().StringVarP(&flagDesc, "description", "d", "", "Description for discovery")

	// Common flags
	root.Flags().StringVarP(&flagEnv, "env", "e", "", "Target environment (default: * baseline)")
	root.Flags().StringVarP(&flagContext, "context", "c", "", "Target context, e.g. tenant/customer (default: * baseline)")
	root.Flags().StringVarP(&flagSource, "source", "S", "", "Target a specific source (primary by default for writes; required when reads are ambiguous)")

	// Discovery flags
	root.Flags().BoolVar(&flagList, "list", false, "List all entries")
	root.Flags().StringVar(&flagDescribe, "describe", "", "Show entry details")
	root.Flags().BoolVar(&flagJSON, "json", false, "JSON output for list/describe/status")

	// Delete flag
	root.Flags().StringVar(&flagDelete, "delete", "", "Delete an entry or specific env/context override")

	historyCmd := &cobra.Command{Use: "history NAME", Short: "Show revision history including values", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		source, _ := cmd.Flags().GetString("source")
		jsonOutput, _ := cmd.Flags().GetBool("json")
		return cli.CmdHistory(args[0], source, jsonOutput)
	}}
	historyCmd.Flags().String("source", "", "Select a source when the entry is ambiguous")
	historyCmd.Flags().Bool("json", false, "JSON output including values")
	root.AddCommand(historyCmd)
	migrateCmd := &cobra.Command{Use: "migrate", Short: "Explicitly migrate one unlocked v2 source to v3", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		source, _ := cmd.Flags().GetString("source")
		return cli.CmdMigrate(source)
	}}
	migrateCmd.Flags().String("source", "", "Source to migrate (default: primary)")
	root.AddCommand(migrateCmd)

	// Subcommands
	initCmd := &cobra.Command{
		Use:   "init",
		Short: "Create a new primary vault or restore with existing passphrase",
		RunE: func(cmd *cobra.Command, args []string) error {
			restore, _ := cmd.Flags().GetBool("restore")
			return cli.CmdInit(restore)
		},
	}
	initCmd.Flags().Bool("restore", false, "Restore with existing passphrase")
	root.AddCommand(initCmd)

	root.AddCommand(&cobra.Command{
		Use:   "unlock",
		Short: "Unlock the primary vault with your passphrase",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cli.CmdUnlock()
		},
	})

	root.AddCommand(&cobra.Command{
		Use:   "lock",
		Short: "Lock the primary vault (clear its session key)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cli.CmdLock()
		},
	})

	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Show primary vault status",
		RunE: func(cmd *cobra.Command, args []string) error {
			j, _ := cmd.Flags().GetBool("json")
			return cli.CmdStatus(j)
		},
	}
	statusCmd.Flags().Bool("json", false, "JSON output")
	root.AddCommand(statusCmd)

	syncCmd := &cobra.Command{
		Use:   "sync",
		Short: "Exchange the primary vault with the sync folder now",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cli.CmdSync()
		},
	}
	syncSetupCmd := &cobra.Command{
		Use:   "setup",
		Short: "Connect the primary vault to a folder a sync service keeps in step",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			path, _ := cmd.Flags().GetString("path")
			return cli.CmdSyncSetup(path)
		},
	}
	syncSetupCmd.Flags().String("path", "", "Existing sync folder")
	syncCmd.AddCommand(syncSetupCmd)
	root.AddCommand(syncCmd)

	// Source subcommands: mount / unmount / list
	sourceCmd := &cobra.Command{
		Use:   "source",
		Short: "Manage mounted secret sources",
	}

	mountCmd := &cobra.Command{
		Use:   "mount",
		Short: "Register a mounted source vault and cache its key",
		RunE: func(cmd *cobra.Command, args []string) error {
			name, _ := cmd.Flags().GetString("name")
			path, _ := cmd.Flags().GetString("path")
			keyHex, _ := cmd.Flags().GetString("key-hex")
			kdf, _ := cmd.Flags().GetString("kdf")
			if name == "" {
				return fmt.Errorf("--name is required")
			}
			if keyHex == "" {
				return fmt.Errorf("--key-hex is required")
			}
			return cli.CmdSourceMount(name, path, keyHex, kdf)
		},
	}
	mountCmd.Flags().String("name", "", "Source name (unique)")
	mountCmd.Flags().String("path", "", "Vault file path")
	mountCmd.Flags().String("key-hex", "", "32-byte key, hex-encoded (64 hex chars)")
	mountCmd.Flags().String("kdf", "raw", "KDF mode: 'raw' (default) or 'argon2id'")
	sourceCmd.AddCommand(mountCmd)

	unmountCmd := &cobra.Command{
		Use:   "unmount",
		Short: "Remove a mounted source (vault file stays on disk)",
		RunE: func(cmd *cobra.Command, args []string) error {
			name, _ := cmd.Flags().GetString("name")
			if name == "" {
				return fmt.Errorf("--name is required")
			}
			return cli.CmdSourceUnmount(name)
		},
	}
	unmountCmd.Flags().String("name", "", "Source name")
	sourceCmd.AddCommand(unmountCmd)

	sourceListCmd := &cobra.Command{
		Use:   "list",
		Short: "List known sources",
		RunE: func(cmd *cobra.Command, args []string) error {
			j, _ := cmd.Flags().GetBool("json")
			return cli.CmdSourceList(j)
		},
	}
	sourceListCmd.Flags().Bool("json", false, "JSON output")
	sourceCmd.AddCommand(sourceListCmd)

	root.AddCommand(sourceCmd)

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func writeValue(flagValue string, valueStdin bool, stdin io.Reader) (string, error) {
	if flagValue != "" && valueStdin {
		return "", fmt.Errorf("--value and --value-stdin are mutually exclusive")
	}
	if valueStdin {
		value, err := io.ReadAll(stdin)
		if err != nil {
			return "", fmt.Errorf("read --value-stdin: %w", err)
		}
		if len(value) == 0 {
			return "", fmt.Errorf("stdin value must not be empty")
		}
		return string(value), nil
	}
	if flagValue == "" {
		return "", fmt.Errorf("--value or --value-stdin is required")
	}
	return flagValue, nil
}
