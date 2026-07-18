package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"naust/daemon/internal/adminops"
)

// recoverCmd is the break-glass account surface used when the admin panel itself
// is unreachable. It is deliberately plain sequential output (no alt-screen TUI)
// so the code path is simple and the transcript is pastable. Sensitive actions
// confirm by re-typing the target email, since fat-fingering the wrong account is
// the real risk in a lockout.
func recoverCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "recover",
		Short: "Break-glass account recovery for when you're locked out of the panel",
	}
	cmd.AddCommand(
		recoverListAdmins(),
		recoverMakeAdmin(),
		recoverPassword(),
		recoverMFADisable(),
		recoverEncryption(),
	)
	return cmd
}

func recoverListAdmins() *cobra.Command {
	return &cobra.Command{
		Use:     "list-admins",
		Short:   "List admin accounts (copy an exact email for the confirm prompts)",
		Args:    cobra.NoArgs,
		PreRunE: preRun,
		RunE: func(cmd *cobra.Command, _ []string) error {
			b, err := openStore()
			if err != nil {
				return err
			}
			defer b.client.Close()
			admins, err := adminops.ListAdmins(context.Background(), b.client)
			if err != nil {
				return err
			}
			if len(admins) == 0 {
				fmt.Println("  No admin accounts.")
				return nil
			}
			fmt.Printf("\n  Admin accounts on %s:\n\n", b.hostname)
			for _, a := range admins {
				mfa := "none"
				switch {
				case a.TOTP && a.Passkeys > 0:
					mfa = fmt.Sprintf("totp+%d passkey(s)", a.Passkeys)
				case a.TOTP:
					mfa = "totp"
				case a.Passkeys > 0:
					mfa = fmt.Sprintf("%d passkey(s)", a.Passkeys)
				}
				fmt.Printf("  %-32s mfa: %s\n", a.Email, mfa)
			}
			fmt.Println()
			return nil
		},
	}
}

func recoverMakeAdmin() *cobra.Command {
	return &cobra.Command{
		Use:     "make-admin <email>",
		Short:   "Grant admin to an account (to get back in)",
		Args:    cobra.ExactArgs(1),
		PreRunE: preRun,
		RunE: func(cmd *cobra.Command, args []string) error {
			email := args[0]
			fmt.Printf("\n  Grant admin privileges to: %s\n", email)
			if err := confirmEmail(email); err != nil {
				return err
			}
			b, err := openStore()
			if err != nil {
				return err
			}
			defer b.client.Close()
			if err := adminops.MakeAdmin(context.Background(), b.client, email); err != nil {
				return err
			}
			fmt.Printf("\n  ✓ %s is now an admin.\n\n", email)
			return nil
		},
	}
}

func recoverPassword() *cobra.Command {
	return &cobra.Command{
		Use:     "password <email>",
		Short:   "Reset an account password and sign out its sessions",
		Args:    cobra.ExactArgs(1),
		PreRunE: preRun,
		RunE: func(cmd *cobra.Command, args []string) error {
			email := args[0]
			fmt.Printf("\n  Reset password for: %s\n\n  This immediately invalidates any active sessions for this account.\n", email)
			pw, err := readNewPassword()
			if err != nil {
				return err
			}
			if err := confirmEmail(email); err != nil {
				return err
			}
			b, err := openStore()
			if err != nil {
				return err
			}
			defer b.client.Close()
			ctx := context.Background()
			revoked, err := adminops.SetPassword(ctx, b.client, email, pw)
			if err != nil {
				return err
			}
			// Push the new hash to Dovecot now, not on the next hourly converge.
			if err := b.materializer().Rebuild(ctx); err != nil {
				return fmt.Errorf("password saved but materialize failed (Dovecot may lag until managerd next converges): %w", err)
			}
			fmt.Printf("\n  ✓ Password reset for %s.\n    %d session(s) signed out.\n\n", email, revoked)
			return nil
		},
	}
}

func recoverMFADisable() *cobra.Command {
	return &cobra.Command{
		Use:     "mfa-disable <email>",
		Short:   "Remove all second factors from an account",
		Args:    cobra.ExactArgs(1),
		PreRunE: preRun,
		RunE: func(cmd *cobra.Command, args []string) error {
			email := args[0]
			fmt.Printf("\n  Disable MFA for: %s\n\n", email)
			fmt.Println("  ! This removes two-factor protection. Anyone with just the password")
			fmt.Println("    will be able to sign in until MFA is re-enrolled.")
			if err := confirmEmail(email); err != nil {
				return err
			}
			b, err := openStore()
			if err != nil {
				return err
			}
			defer b.client.Close()
			totp, passkeys, err := adminops.DisableMFA(context.Background(), b.client, email)
			if err != nil {
				return err
			}
			fmt.Printf("\n  ✓ MFA disabled for %s (%d totp, %d passkey(s) removed).\n", email, totp, passkeys)
			fmt.Println("    Recommend the account owner re-enroll MFA once they can sign in.")
			fmt.Println()
			return nil
		},
	}
}

func recoverEncryption() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "encryption",
		Short: "Inspect or remove at-rest encryption key slots",
	}
	cmd.AddCommand(
		&cobra.Command{
			Use:     "status <email>",
			Short:   "Show an account's encryption key slots",
			Args:    cobra.ExactArgs(1),
			PreRunE: preRun,
			RunE: func(cmd *cobra.Command, args []string) error {
				b, err := openStore()
				if err != nil {
					return err
				}
				defer b.client.Close()
				slots, err := adminops.EncryptionStatus(context.Background(), b.client, args[0])
				if err != nil {
					return err
				}
				if len(slots) == 0 {
					fmt.Printf("  %s - encryption disabled (no key slots)\n", args[0])
					return nil
				}
				fmt.Printf("  %s - encryption enabled\n", args[0])
				for _, s := range slots {
					fmt.Printf("    %s:%s\n", s.Type, s.Label)
				}
				return nil
			},
		},
		&cobra.Command{
			Use:     "list",
			Short:   "List every account with at-rest encryption",
			Args:    cobra.NoArgs,
			PreRunE: preRun,
			RunE: func(cmd *cobra.Command, _ []string) error {
				b, err := openStore()
				if err != nil {
					return err
				}
				defer b.client.Close()
				list, err := adminops.EncryptionList(context.Background(), b.client)
				if err != nil {
					return err
				}
				if len(list) == 0 {
					fmt.Println("  No accounts have encryption enabled.")
					return nil
				}
				for _, u := range list {
					fmt.Println(u.Email)
					for _, s := range u.Slots {
						fmt.Printf("    %s\n", s.Type)
					}
				}
				return nil
			},
		},
		&cobra.Command{
			Use:     "disable <email>",
			Short:   "Remove an account's key slots (encrypted mail becomes unrecoverable)",
			Args:    cobra.ExactArgs(1),
			PreRunE: preRun,
			RunE: func(cmd *cobra.Command, args []string) error {
				email := args[0]
				fmt.Printf("\n  ! Removing all encryption key slots for %s.\n", email)
				fmt.Println("    Any mail encrypted at rest will be PERMANENTLY UNRECOVERABLE.")
				if err := confirmEmail(email); err != nil {
					return err
				}
				b, err := openStore()
				if err != nil {
					return err
				}
				defer b.client.Close()
				removed, err := adminops.EncryptionDisable(context.Background(), b.client, email)
				if err != nil {
					return err
				}
				fmt.Printf("\n  ✓ Removed %d key slot(s) for %s. Encryption is now disabled.\n\n", removed, email)
				return nil
			},
		},
	)
	return cmd
}

// preRun re-execs as naust before any store-touching recover command.
func preRun(*cobra.Command, []string) error { return ensureNaust() }

// confirmEmail requires the operator to retype the exact target address, the last
// gate before a write - the defense against acting on the wrong account.
func confirmEmail(target string) error {
	fmt.Printf("\n  Type the account email to confirm: ")
	return confirmEmailFrom(os.Stdin, target)
}

// confirmEmailFrom is the pure core of confirmEmail: read one line, require it to
// match target exactly after trimming surrounding whitespace. Split out so the
// wrong-account gate can be exercised without a real terminal.
func confirmEmailFrom(r io.Reader, target string) error {
	line, err := bufio.NewReader(r).ReadString('\n')
	if err != nil && strings.TrimSpace(line) == "" {
		return errors.New("aborted")
	}
	if strings.TrimSpace(line) != target {
		return errors.New("confirmation did not match; aborted")
	}
	return nil
}

// readNewPassword reads and confirms a new password with masked entry, reusing
// the same minimum the panel enforced. A mismatch re-prompts both fields.
func readNewPassword() (string, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", errors.New("password entry requires an interactive terminal")
	}
	for {
		fmt.Printf("\n  New password: ")
		first, err := term.ReadPassword(fd)
		if err != nil {
			return "", err
		}
		fmt.Printf("\n  Confirm:      ")
		second, err := term.ReadPassword(fd)
		if err != nil {
			return "", err
		}
		fmt.Println()
		if len(first) == 0 {
			fmt.Println("  Password must not be empty. Try again.")
			continue
		}
		if string(first) != string(second) {
			fmt.Println("  Passwords did not match. Try again.")
			continue
		}
		return string(first), nil
	}
}
