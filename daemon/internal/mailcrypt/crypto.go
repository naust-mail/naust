// Package mailcrypt implements the key-slot model for encryption at
// rest.
//
// Each user has one random 32-byte root key. It is never stored in the
// clear and never leaves this package: consumers receive purpose-bound
// subkeys derived with HKDF (Dovecot's mail_crypt keypair password is
// the "dovecot" subkey). The root key is wrapped (AES-256-GCM) under
// one or more independent slots, each derived from a different secret
// the user controls:
//
//	slot_type      secret                     KDF
//	------------   ------------------------   --------------------------
//	password       the account password       Argon2id(t=3, m=64MiB, p=4)
//	recovery_code  a printed recovery code    HKDF-SHA256(code, salt)
//	passkey_prf    WebAuthn PRF output        HKDF-SHA256(output, salt)
//	app_password   reserved, not yet minted
//
// Any single slot unwraps the root key. There is no master key: a user
// who loses every slot secret has unrecoverable mail by design.
//
// Every wrap binds the slot's context (user ID, slot type, label,
// version) as GCM associated data, so a row moved between users or
// slot types fails authentication. The version field exists so future
// KDF parameter changes can re-wrap lazily on the next successful
// unwrap instead of needing a flag day.
package mailcrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

// SlotVersion is written to new slots and bound into their AAD.
// Version 1 = Argon2id(t=3, m=64MiB, p=4) / HKDF-SHA256 / AES-256-GCM.
const SlotVersion = 1

const (
	keyLen      = 32
	saltLen     = 32
	gcmNonceLen = 12

	argonTime      = 3
	argonMemoryKiB = 64 * 1024
	argonLanes     = 4
)

// hkdfSlotInfo domain-separates slot wrapping keys from every other
// HKDF use in the codebase.
const hkdfSlotInfo = "naust mailcrypt v1: slot"

// subkeyInfoPrefix prefixes the purpose label when deriving consumer
// subkeys from the root key.
const subkeyInfoPrefix = "naust mailcrypt v1: "

// SubkeyDovecot is the purpose label for the Dovecot mail_crypt
// keypair password. The raw root key is never handed to Dovecot.
const SubkeyDovecot = "dovecot"

// argonSlots caps concurrent Argon2id derivations. Each run costs
// 64MiB; an IMAP login burst on a cold passdb cache would otherwise
// multiply that without bound.
var argonSlots = make(chan struct{}, 2)

// GenerateRootKey returns a fresh random 32-byte root key.
func GenerateRootKey() ([]byte, error) {
	return randomBytes(keyLen)
}

// GenerateSalt returns a fresh random 32-byte KDF salt.
func GenerateSalt() ([]byte, error) {
	return randomBytes(saltLen)
}

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// DeriveKeyFromPassword derives a 32-byte wrapping key from the login
// password with Argon2id. Blocks while more than two derivations are
// already running.
func DeriveKeyFromPassword(password string, salt []byte) []byte {
	argonSlots <- struct{}{}
	defer func() { <-argonSlots }()
	return argon2.IDKey([]byte(password), salt, argonTime, argonMemoryKiB, argonLanes, keyLen)
}

// DeriveKeyFromSecret derives a 32-byte wrapping key from a
// high-entropy secret (recovery code, PRF output) with HKDF-SHA256.
func DeriveKeyFromSecret(secret, salt []byte) ([]byte, error) {
	key := make([]byte, keyLen)
	r := hkdf.New(sha256.New, secret, salt, []byte(hkdfSlotInfo))
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, err
	}
	return key, nil
}

// Subkey derives the purpose-bound consumer key from the root key.
// Purposes are fixed strings (SubkeyDovecot, ...); two purposes never
// see each other's key material.
func Subkey(rootKey []byte, purpose string) ([]byte, error) {
	key := make([]byte, keyLen)
	r := hkdf.New(sha256.New, rootKey, nil, []byte(subkeyInfoPrefix+purpose))
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, err
	}
	return key, nil
}

// slotAAD binds a wrapped key to its database context. Any field
// changing (row copied to another user, relabelled, re-typed, version
// tampered) makes GCM authentication fail.
func slotAAD(userID int, slotType, label string, version int) []byte {
	return fmt.Appendf(nil, "naust slot v%d|%d|%s|%s", version, userID, slotType, label)
}

// Wrap encrypts the root key under a wrapping key, bound to the slot's
// context. Returns (ciphertext, nonce); the nonce is random per call.
func Wrap(rootKey, wrappingKey []byte, userID int, slotType, label string, version int) (ciphertext, nonce []byte, err error) {
	aead, err := newGCM(wrappingKey)
	if err != nil {
		return nil, nil, err
	}
	nonce, err = randomBytes(gcmNonceLen)
	if err != nil {
		return nil, nil, err
	}
	ciphertext = aead.Seal(nil, nonce, rootKey, slotAAD(userID, slotType, label, version))
	return ciphertext, nonce, nil
}

// Unwrap decrypts a wrapped root key. Fails if the wrapping key is
// wrong or the slot context does not match the one it was sealed with.
func Unwrap(ciphertext, nonce, wrappingKey []byte, userID int, slotType, label string, version int) ([]byte, error) {
	aead, err := newGCM(wrappingKey)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ciphertext, slotAAD(userID, slotType, label, version))
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
