package mailcrypt

import (
	"crypto/rand"
	"strings"
)

// Recovery codes: 16 Crockford base32 characters printed as four
// dash-separated groups (A3K7-9MNP-2QRT-X5BC). The first 15 characters
// are random data (75 bits); the last is a position-weighted checksum
// mod 37, reject-sampled at generation so it always lands inside the
// 32-symbol alphabet. Mod 37 (prime) catches adjacent transpositions
// that a mod-32 sum would miss.

const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

const (
	recoveryDataLen  = 15
	recoveryTotalLen = 16
	// RecoveryCodeCount is how many codes a setup or rotation issues.
	RecoveryCodeCount = 4
)

var crockfordIndex = func() map[byte]int {
	m := make(map[byte]int, len(crockford))
	for i := 0; i < len(crockford); i++ {
		m[crockford[i]] = i
	}
	return m
}()

// checksum is the position-weighted sum of the data character values,
// mod 37. The weight (i+1) makes it sensitive to transposition.
func checksum(dataValues []int) int {
	sum := 0
	for i, v := range dataValues {
		sum += v * (i + 1)
	}
	return sum % 37
}

// NormalizeRecoveryCode uppercases, strips dashes and whitespace, and
// applies Crockford input aliasing (O reads as 0, I and L as 1). Codes
// are compared and key-derived in this form.
func NormalizeRecoveryCode(code string) string {
	s := strings.ToUpper(strings.TrimSpace(code))
	s = strings.NewReplacer("-", "", " ", "", "O", "0", "I", "1", "L", "1").Replace(s)
	return s
}

// GenerateRecoveryCodes returns RecoveryCodeCount formatted codes.
func GenerateRecoveryCodes() ([]string, error) {
	codes := make([]string, RecoveryCodeCount)
	for i := range codes {
		c, err := generateOneRecoveryCode()
		if err != nil {
			return nil, err
		}
		codes[i] = c
	}
	return codes, nil
}

func generateOneRecoveryCode() (string, error) {
	for {
		raw := make([]byte, recoveryDataLen)
		if _, err := rand.Read(raw); err != nil {
			return "", err
		}
		dataValues := make([]int, recoveryDataLen)
		for i, b := range raw {
			dataValues[i] = int(b % 32)
		}
		cs := checksum(dataValues)
		if cs >= 32 {
			continue
		}
		chars := make([]byte, 0, recoveryTotalLen)
		for _, v := range dataValues {
			chars = append(chars, crockford[v])
		}
		chars = append(chars, crockford[cs])
		groups := make([]string, 0, 4)
		for i := 0; i < recoveryTotalLen; i += 4 {
			groups = append(groups, string(chars[i:i+4]))
		}
		return strings.Join(groups, "-"), nil
	}
}

// ValidRecoveryCodeCRC reports whether a code has exactly 16
// in-alphabet characters and a matching checksum. Cheap fast-fail for
// typos before any KDF or database work.
func ValidRecoveryCodeCRC(code string) bool {
	s := NormalizeRecoveryCode(code)
	if len(s) != recoveryTotalLen {
		return false
	}
	dataValues := make([]int, recoveryDataLen)
	for i := 0; i < recoveryTotalLen; i++ {
		v, ok := crockfordIndex[s[i]]
		if !ok {
			return false
		}
		if i < recoveryDataLen {
			dataValues[i] = v
		}
	}
	cs := checksum(dataValues)
	return cs < 32 && crockford[cs] == s[recoveryDataLen]
}
