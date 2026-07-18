package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// TOTP per RFC 6238: HMAC-SHA1, 30-second steps, 6 digits, one step of
// clock skew accepted either way. Replay is prevented by the caller
// persisting the matched step and refusing older ones (atomic consume
// in the store), which is why Verify returns the step.

const totpStep = 30

// NewTOTPSecret generates a 160-bit secret, base32 (what authenticator
// apps expect), 32 characters.
func NewTOTPSecret() (string, error) {
	raw := make([]byte, 20)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base32.StdEncoding.EncodeToString(raw), nil
}

// ValidateTOTPSecret checks the shape of a client-supplied secret.
func ValidateTOTPSecret(secret string) error {
	if len(secret) != 32 {
		return fmt.Errorf("secret must be a 32-character base32 string")
	}
	if _, err := base32.StdEncoding.DecodeString(secret); err != nil {
		return fmt.Errorf("secret must be a 32-character base32 string")
	}
	return nil
}

// TOTPURI builds the otpauth: provisioning URI that authenticator apps
// import (rendered as a QR code client-side).
func TOTPURI(secret, account, issuer string) string {
	return "otpauth://totp/" + url.PathEscape(issuer+":"+account) +
		"?secret=" + secret +
		"&issuer=" + url.QueryEscape(issuer)
}

// VerifyTOTP checks code against secret at time t, accepting one step
// of skew in each direction. On success it returns the step that
// matched so the caller can consume it.
func VerifyTOTP(secret, code string, t time.Time) (matchedStep int64, ok bool) {
	key, err := base32.StdEncoding.DecodeString(strings.ToUpper(secret))
	if err != nil {
		return 0, false
	}
	step := t.Unix() / totpStep
	for _, s := range []int64{step, step - 1, step + 1} {
		if subtle.ConstantTimeCompare([]byte(totpCode(key, s)), []byte(code)) == 1 {
			return s, true
		}
	}
	return 0, false
}

func totpCode(key []byte, step int64) string {
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(step))
	mac := hmac.New(sha1.New, key)
	mac.Write(counter[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0xf
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", value%1_000_000)
}

// FormatTOTPStep renders a step counter for storage in the mru_token
// column. Zero-padded so string comparison orders correctly across
// digit-count boundaries.
func FormatTOTPStep(step int64) string {
	return fmt.Sprintf("%012d", step)
}

// TOTPCodeForTest exposes code generation so tests elsewhere can play
// the authenticator app. Not for production use: verification goes
// through VerifyTOTP.
func TOTPCodeForTest(key []byte, step int64) string {
	return totpCode(key, step)
}
