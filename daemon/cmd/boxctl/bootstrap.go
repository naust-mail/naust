package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"

	entuser "naust/daemon/internal/store/ent/user"
)

// bootstrapToken is the on-disk setup-code state at STORAGE_ROOT/control/
// bootstrap.token. managerd (internal/httpapi/bootstrap.go) reads these exact
// fields, manages Attempts, and deletes the file when the code is consumed or
// locked out - so this command only ever mints; it never edits an existing token.
type bootstrapToken struct {
	Code     string `json:"code"`
	Expires  int64  `json:"expires"`
	Attempts int    `json:"attempts"`
}

const (
	// bootstrapCodeChars omits look-alikes (0/O, 1/I/L) since the code is read
	// off a terminal and typed into a browser by hand.
	bootstrapCodeChars = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
	bootstrapCodeLen   = 8
	// bootstrapTTL matches the window managerd enforces on Expires.
	bootstrapTTL = 15 * time.Minute
)

// bootstrapCmd mints a one-time setup code that unlocks first-admin creation in
// the web UI. It is the sole writer of the token managerd gates on: because the
// setup repo can be deleted after install, this must live in the installed
// binary so an operator whose code expired can always mint a new one.
func bootstrapCmd() *cobra.Command {
	var showCert, install bool
	cmd := &cobra.Command{
		Use:     "bootstrap",
		Short:   "Mint a one-time setup code to create the first admin account",
		Args:    cobra.NoArgs,
		PreRunE: preRun,
		RunE: func(cmd *cobra.Command, _ []string) error {
			b, err := openStore()
			if err != nil {
				return err
			}
			defer b.client.Close()
			ctx := context.Background()

			admins, err := b.client.User.Query().Where(entuser.RoleEQ(entuser.RoleAdmin)).Count(ctx)
			if err != nil {
				return fmt.Errorf("count admins: %w", err)
			}
			if admins > 0 {
				// The box is already claimed: managerd's endpoint is inert, so a
				// fresh code would be useless. On a setup re-run the installer
				// still wants the completion panel; a bare operator run gets a
				// plain refusal.
				if install {
					printSetupComplete(b, showCert)
					return nil
				}
				return errors.New("an admin account already exists; bootstrap is not available")
			}

			code, err := bootstrapCode()
			if err != nil {
				return err
			}
			tok := newBootstrapToken(code, time.Now())
			tokenPath := filepath.Join(b.storageRoot, "control", "bootstrap.token")
			if err := writeBootstrapToken(tokenPath, tok); err != nil {
				return fmt.Errorf("write bootstrap token: %w", err)
			}
			printWelcome(b, code, tok, showCert)
			return nil
		},
	}
	cmd.Flags().BoolVar(&showCert, "show-cert", false, "print the box's TLS certificate fingerprint")
	cmd.Flags().BoolVar(&install, "install", false, "installer mode: on an already-set-up box, show the completion panel instead of erroring")
	return cmd
}

// bootstrapCode draws bootstrapCodeLen characters from the unambiguous alphabet
// using crypto/rand, so a network attacker cannot predict the setup code.
func bootstrapCode() (string, error) {
	var b strings.Builder
	max := big.NewInt(int64(len(bootstrapCodeChars)))
	for i := 0; i < bootstrapCodeLen; i++ {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", fmt.Errorf("generate setup code: %w", err)
		}
		b.WriteByte(bootstrapCodeChars[n.Int64()])
	}
	return b.String(), nil
}

// newBootstrapToken builds the token for a freshly minted code.
func newBootstrapToken(code string, now time.Time) bootstrapToken {
	return bootstrapToken{Code: code, Expires: now.Add(bootstrapTTL).Unix(), Attempts: 0}
}

// writeBootstrapToken atomically writes the token 0600 (tmp + rename) so a reader
// never sees a half-written file. The process already runs as naust (ensureNaust),
// so the file and control/ directory stay naust-owned for managerd to rewrite.
func writeBootstrapToken(path string, tok bootstrapToken) error {
	data, err := json.Marshal(tok)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// certFingerprint returns the SHA-256 fingerprint of the box's TLS certificate,
// colon-separated uppercase hex (the same value openssl x509 -fingerprint prints),
// so an operator connecting by IP can verify they reached the right box. Empty
// when the certificate is missing or unparseable - a display nicety, not a gate.
func certFingerprint(storageRoot string) string {
	raw, err := os.ReadFile(filepath.Join(storageRoot, "ssl", "ssl_certificate.pem"))
	if err != nil {
		return ""
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return ""
	}
	// Parse before hashing: a corrupt file whose body still happens to be valid
	// base64 would otherwise produce a plausible-looking but wrong fingerprint,
	// which is worse than showing none when an operator is verifying the box.
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(cert.Raw)
	parts := make([]string, len(sum))
	for i, by := range sum {
		parts[i] = fmt.Sprintf("%02X", by)
	}
	return strings.Join(parts, ":")
}

var bootstrapBold = lipgloss.NewStyle().Bold(true)

// printWelcome renders the setup-code panel: the code to type, the URL to open,
// and how long the operator has before it expires.
func printWelcome(b *boxStore, code string, tok bootstrapToken, showCert bool) {
	rule := chrome.Render(strings.Repeat("─", 60))
	url := fmt.Sprintf("https://%s/admin/setup?code=%s", b.hostname, code)
	expiry := time.Unix(tok.Expires, 0).Format("15:04:05")
	display := code[:4] + " " + code[4:]

	fmt.Println()
	fmt.Printf("  %s\n", bootstrapBold.Render("Welcome to Naust"))
	fmt.Printf("  %s\n", rule)
	fmt.Printf("  %-16s %s\n", "Setup code", okStyle.Bold(true).Render(display))
	fmt.Printf("  %-16s %s\n", "Open", accent.Render(url))
	if b.publicIP != "" {
		fmt.Printf("  %-16s %s\n", "Or (by IP)", secondary.Render(fmt.Sprintf("https://%s/admin/setup?code=%s", b.publicIP, code)))
	}
	fmt.Printf("  %-16s %s\n", "Code expires", secondary.Render(expiry+" (15 minutes)"))
	if showCert {
		if fp := certFingerprint(b.storageRoot); fp != "" {
			fmt.Printf("  %-16s %s\n", "TLS fingerprint", secondary.Render(fp))
		}
	}
	fmt.Printf("  %s\n", rule)
	fmt.Printf("  %s\n", secondary.Render("Enter the code on the setup page, or open the link above."))
	fmt.Printf("  %s\n\n", secondary.Render("Run sudo boxctl bootstrap if the code expires."))
}

// printSetupComplete renders the completion panel shown when the box is already
// claimed (a setup re-run under --install), pointing at the live admin panel.
func printSetupComplete(b *boxStore, showCert bool) {
	rule := chrome.Render(strings.Repeat("─", 60))
	fmt.Println()
	fmt.Printf("  %s\n", bootstrapBold.Render("Naust setup complete."))
	fmt.Printf("  %s\n", rule)
	fmt.Printf("  %-16s %s\n", "Admin panel", accent.Render(fmt.Sprintf("https://%s/admin", b.hostname)))
	if showCert {
		if fp := certFingerprint(b.storageRoot); fp != "" {
			fmt.Printf("  %-16s %s\n", "TLS fingerprint", secondary.Render(fp))
		}
	}
	fmt.Printf("  %s\n\n", rule)
}
