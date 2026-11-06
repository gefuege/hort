package main

import (
	"fmt"
	"io"
	"os"

	"github.com/gefuege/hort/internal/cli"
	"github.com/gefuege/hort/internal/helptext"
	"github.com/spf13/cobra"
)

func main() {
	root := &cobra.Command{
		Use:           "hort",
		Short:         "Hort — Local secret store for humans and AI agents",
		Long:          helptext.HelpText,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	// scopeFlags adds the --env/--context pair shared by get, set and delete.
	scopeFlags := func(c *cobra.Command) {
		c.Flags().StringP("env", "e", "", "Environment (default: * baseline)")
		c.Flags().StringP("context", "c", "", "Context, e.g. tenant/customer (default: * baseline)")
	}
	jsonFlag := func(c *cobra.Command, usage string) {
		c.Flags().Bool("json", false, usage)
	}

	getCmd := &cobra.Command{
		Use:   "get NAME [FIELD]",
		Short: "Print a value (stdout only)",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			env, _ := cmd.Flags().GetString("env")
			context, _ := cmd.Flags().GetString("context")
			return cli.CmdGet(args[0], optionalField(args), env, context)
		},
	}
	scopeFlags(getCmd)
	root.AddCommand(getCmd)

	setCmd := &cobra.Command{
		Use:   "set NAME [FIELD]",
		Short: "Store a value",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			env, _ := cmd.Flags().GetString("env")
			context, _ := cmd.Flags().GetString("context")
			desc, _ := cmd.Flags().GetString("description")
			flagValue, _ := cmd.Flags().GetString("value")
			valueStdin, _ := cmd.Flags().GetBool("value-stdin")
			value, err := writeValue(flagValue, valueStdin, cmd.InOrStdin())
			if err != nil {
				return fmt.Errorf("set: %w", err)
			}
			return cli.CmdSet(args[0], optionalField(args), value, env, context, desc)
		},
	}
	scopeFlags(setCmd)
	setCmd.Flags().StringP("value", "v", "", "Value to store")
	setCmd.Flags().Bool("value-stdin", false, "Read the value to store from stdin")
	setCmd.Flags().StringP("description", "d", "", "Description of the whole entry, for discovery")
	root.AddCommand(setCmd)

	deleteCmd := &cobra.Command{
		Use:   "delete NAME [FIELD]",
		Short: "Delete an entry, or one value of it",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			env, _ := cmd.Flags().GetString("env")
			context, _ := cmd.Flags().GetString("context")
			return cli.CmdDelete(args[0], optionalField(args), env, context)
		},
	}
	scopeFlags(deleteCmd)
	root.AddCommand(deleteCmd)

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List all entries (metadata only)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			j, _ := cmd.Flags().GetBool("json")
			return cli.CmdList(j)
		},
	}
	jsonFlag(listCmd, "JSON output")
	root.AddCommand(listCmd)

	describeCmd := &cobra.Command{
		Use:   "describe NAME",
		Short: "Show one entry (metadata only)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			j, _ := cmd.Flags().GetBool("json")
			return cli.CmdDescribe(args[0], j)
		},
	}
	jsonFlag(describeCmd, "JSON output")
	root.AddCommand(describeCmd)

	searchCmd := &cobra.Command{
		Use:   "search TERMS...",
		Short: "Search names, descriptions, fields and scopes (metadata only)",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			j, _ := cmd.Flags().GetBool("json")
			return cli.CmdSearch(args, j)
		},
	}
	jsonFlag(searchCmd, "JSON output")
	root.AddCommand(searchCmd)

	historyCmd := &cobra.Command{
		Use:   "history NAME",
		Short: "Show revision history including values",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			j, _ := cmd.Flags().GetBool("json")
			return cli.CmdHistory(args[0], j)
		},
	}
	jsonFlag(historyCmd, "JSON output including values")
	root.AddCommand(historyCmd)

	// recovery is a help topic: it has no Run, so `hort help recovery` shows it.
	root.AddCommand(&cobra.Command{
		Use:   "recovery",
		Short: "What can and cannot be recovered",
		Long:  helptext.RecoveryText,
	})

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

	root.AddCommand(&cobra.Command{
		Use:   "migrate",
		Short: "Convert a v3 vault into a v4 vault once",
		Long:  helptext.MigrateText,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cli.CmdMigrate()
		},
	})

	syncCmd := &cobra.Command{
		Use:   "sync",
		Short: "Sync with the server; the first run registers the account",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			j, _ := cmd.Flags().GetBool("json")
			return cli.CmdSync(j)
		},
	}
	jsonFlag(syncCmd, "JSON output {pulled, pushed, skipped_invalid, cursor}")
	root.AddCommand(syncCmd)

	enrollCmd := &cobra.Command{
		Use:   "enroll ACCOUNT_ID",
		Short: "Add this device to an existing account (needs no vault here)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			server, _ := cmd.Flags().GetString("server")
			name, _ := cmd.Flags().GetString("name")
			return cli.CmdEnroll(args[0], server, name)
		},
	}
	enrollCmd.Flags().String("server", "", "Sync server URL (default https://hort.pm)")
	enrollCmd.Flags().String("name", "", "Name of this device (default <os>-<4 random chars>)")
	root.AddCommand(enrollCmd)

	devicesCmd := &cobra.Command{
		Use:   "devices",
		Short: "List the devices of this account",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			j, _ := cmd.Flags().GetBool("json")
			return cli.CmdDevices(j)
		},
	}
	jsonFlag(devicesCmd, "JSON output")
	devicesCmd.AddCommand(&cobra.Command{
		Use:   "revoke DEVICE_ID",
		Short: "End a device's server access",
		Long:  "End a device's server access. " + cli.RevokeNote,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return cli.CmdRevokeDevice(args[0])
		},
	})
	root.AddCommand(devicesCmd)

	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Show local vault status",
		Args:  cobra.NoArgs,
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

// optionalField is the second positional argument: the field, "" for the default.
func optionalField(args []string) string {
	if len(args) > 1 {
		return args[1]
	}
	return ""
}
