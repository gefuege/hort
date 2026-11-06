package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/gefuege/hort/internal/cli"
	"github.com/gefuege/hort/internal/helptext"
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
				return cli.CmdGetSecret(flagSecret, flagEnv, flagContext)
			}
			if flagSetSecret != "" {
				value, err := writeValue(flagValue, flagValueStdin, cmd.InOrStdin())
				if err != nil {
					return fmt.Errorf("set secret: %w", err)
				}
				return cli.CmdSetSecret(flagSetSecret, value, flagEnv, flagContext, flagDesc)
			}
			if flagList {
				return cli.CmdList(flagJSON)
			}
			if flagDescribe != "" {
				return cli.CmdDescribe(flagDescribe, flagJSON)
			}
			if flagDelete != "" {
				return cli.CmdDelete(flagDelete, flagEnv, flagContext)
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

	// Discovery flags
	root.Flags().BoolVar(&flagList, "list", false, "List all entries")
	root.Flags().StringVar(&flagDescribe, "describe", "", "Show entry details")
	root.Flags().BoolVar(&flagJSON, "json", false, "JSON output for list/describe/status")

	// Delete flag
	root.Flags().StringVar(&flagDelete, "delete", "", "Delete an entry or specific env/context override")

	historyCmd := &cobra.Command{Use: "history NAME", Short: "Show revision history including values", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		jsonOutput, _ := cmd.Flags().GetBool("json")
		return cli.CmdHistory(args[0], jsonOutput)
	}}
	historyCmd.Flags().Bool("json", false, "JSON output including values")
	root.AddCommand(historyCmd)

	// Subcommands
	initCmd := &cobra.Command{
		Use:   "init",
		Short: "Create a new vault and print its Emergency Kit",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			server, _ := cmd.Flags().GetString("server")
			name, _ := cmd.Flags().GetString("name")
			return cli.CmdInit(server, name)
		},
	}
	initCmd.Flags().String("server", "", "Sync server URL (default https://hort.pm)")
	initCmd.Flags().String("name", "", "Name of this device (default <os>-<4 random chars>)")
	root.AddCommand(initCmd)

	root.AddCommand(&cobra.Command{
		Use:   "unlock",
		Short: "Unlock the vault with your passphrase and Secret Key",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cli.CmdUnlock()
		},
	})

	root.AddCommand(&cobra.Command{
		Use:   "lock",
		Short: "Lock the vault (clear its session key)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cli.CmdLock()
		},
	})

	root.AddCommand(&cobra.Command{
		Use:   "kit",
		Short: "Print the Emergency Kit again",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cli.CmdKit()
		},
	})

	root.AddCommand(&cobra.Command{
		Use:   "passphrase",
		Short: "Set a new passphrase, keeping the Secret Key",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cli.CmdPassphrase()
		},
	})

	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Show local vault status",
		RunE: func(cmd *cobra.Command, args []string) error {
			j, _ := cmd.Flags().GetBool("json")
			return cli.CmdStatus(j)
		},
	}
	statusCmd.Flags().Bool("json", false, "JSON output")
	root.AddCommand(statusCmd)

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
