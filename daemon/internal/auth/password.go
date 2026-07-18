// Package auth implements credential verification and DB-backed
// sessions for managerd. Password hashes use Dovecot's {SCHEME}hash
// format because the same hash is materialized to Dovecot for IMAP
// auth - one credential, verified identically on both paths.
package auth

import (
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

const blfPrefix = "{BLF-CRYPT}"

// Cost 12 matches passlib's default used by the Python daemon, so
// hashes stay interchangeable across the rewrite boundary. Test
// binaries use bcrypt.MinCost instead: still real bcrypt, just cheap
// enough that the many hashes generated across a test suite don't
// dominate its runtime - especially under -race, whose per-memory-access
// instrumentation compounds with bcrypt's deliberately expensive inner
// loop badly enough to blow past a 20-minute timeout at cost 12.
var bcryptCost = 12

func init() {
	if testing.Testing() {
		bcryptCost = bcrypt.MinCost
	}
}

// HashPassword returns a Dovecot-format {BLF-CRYPT} bcrypt hash.
func HashPassword(pw string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcryptCost)
	if err != nil {
		return "", err
	}
	return blfPrefix + string(h), nil
}

var (
	dummyOnce sync.Once
	dummyHash []byte
)

// FakeVerify burns the same bcrypt cost as a real verification so that
// unknown-user and wrong-password login failures take the same time,
// preventing account enumeration by response timing.
func FakeVerify(pw string) {
	dummyOnce.Do(func() {
		dummyHash, _ = bcrypt.GenerateFromPassword([]byte("timing-equalizer"), bcryptCost)
	})
	_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(pw))
}

// VerifyPassword checks pw against a stored {SCHEME}hash. Only
// BLF-CRYPT is accepted: the Go daemon postdates the fork's move to
// bcrypt and no deployed data predates it (constraints window), so
// there is no legacy SHA512-CRYPT to honor.
func VerifyPassword(hash, pw string) bool {
	rest, ok := strings.CutPrefix(hash, blfPrefix)
	if !ok {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(rest), []byte(pw)) == nil
}
