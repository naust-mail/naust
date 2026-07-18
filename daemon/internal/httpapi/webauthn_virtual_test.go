package httpapi

// A minimal virtual authenticator: enough of the WebAuthn data
// formats (ES256, attestation "none") to complete real register and
// assertion ceremonies against the library, including a simulated prf
// extension. No browser stubbing - the server-side verification path
// runs for real.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"strconv"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

type virtualAuthenticator struct {
	key       *ecdsa.PrivateKey
	credID    []byte
	rpID      string
	origin    string
	signCount uint32
	// prfSeed makes the simulated PRF deterministic per credential:
	// output = HMAC-SHA256(prfSeed, salt), mirroring how real
	// authenticators derive hmac-secret outputs.
	prfSeed []byte
}

func newVirtualAuthenticator(t *testing.T, rpID string) *virtualAuthenticator {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	credID := make([]byte, 16)
	seed := make([]byte, 32)
	rand.Read(credID)
	rand.Read(seed)
	return &virtualAuthenticator{
		key:     key,
		credID:  credID,
		rpID:    rpID,
		origin:  "https://" + rpID,
		prfSeed: seed,
	}
}

func (a *virtualAuthenticator) prf(salt []byte) []byte {
	mac := hmac.New(sha256.New, a.prfSeed)
	mac.Write(salt)
	return mac.Sum(nil)
}

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// challengeFrom pulls publicKey.challenge out of a begin response's
// options JSON.
func challengeFrom(t *testing.T, options []byte) string {
	t.Helper()
	var wrapper struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(options, &wrapper); err != nil {
		t.Fatal(err)
	}
	if wrapper.PublicKey.Challenge == "" {
		t.Fatalf("no challenge in options: %s", options)
	}
	return wrapper.PublicKey.Challenge
}

func (a *virtualAuthenticator) clientData(t *testing.T, typ, challenge string) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]string{
		"type":      typ,
		"challenge": challenge,
		"origin":    a.origin,
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// attest produces the registration response JSON for a challenge.
func (a *virtualAuthenticator) attest(t *testing.T, challenge string) []byte {
	t.Helper()
	rpHash := sha256.Sum256([]byte(a.rpID))

	x := a.key.PublicKey.X.FillBytes(make([]byte, 32))
	y := a.key.PublicKey.Y.FillBytes(make([]byte, 32))
	coseKey, err := cbor.Marshal(map[int]any{
		1: 2, 3: -7, -1: 1, -2: x, -3: y,
	})
	if err != nil {
		t.Fatal(err)
	}

	// authData: rpIdHash | flags(UP|UV|AT) | signCount | attestedCredentialData
	authData := append([]byte{}, rpHash[:]...)
	authData = append(authData, 0x45)
	authData = append(authData, 0, 0, 0, 0)
	authData = append(authData, make([]byte, 16)...) // zero AAGUID
	credLen := make([]byte, 2)
	binary.BigEndian.PutUint16(credLen, uint16(len(a.credID)))
	authData = append(authData, credLen...)
	authData = append(authData, a.credID...)
	authData = append(authData, coseKey...)

	attObj, err := cbor.Marshal(map[string]any{
		"fmt":      "none",
		"attStmt":  map[string]any{},
		"authData": authData,
	})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := json.Marshal(map[string]any{
		"id":    b64u(a.credID),
		"rawId": b64u(a.credID),
		"type":  "public-key",
		"response": map[string]string{
			"attestationObject": b64u(attObj),
			"clientDataJSON":    b64u(a.clientData(t, "webauthn.create", challenge)),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// assert produces an assertion response JSON for a challenge.
// userHandle is the account's WebAuthn user ID.
func (a *virtualAuthenticator) assert(t *testing.T, challenge string, userID int) []byte {
	t.Helper()
	rpHash := sha256.Sum256([]byte(a.rpID))
	a.signCount++

	// authData: rpIdHash | flags(UP|UV) | signCount
	authData := append([]byte{}, rpHash[:]...)
	authData = append(authData, 0x05)
	count := make([]byte, 4)
	binary.BigEndian.PutUint32(count, a.signCount)
	authData = append(authData, count...)

	clientData := a.clientData(t, "webauthn.get", challenge)
	clientHash := sha256.Sum256(clientData)
	signed := append(append([]byte{}, authData...), clientHash[:]...)
	digest := sha256.Sum256(signed)
	sig, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}

	resp, err := json.Marshal(map[string]any{
		"id":    b64u(a.credID),
		"rawId": b64u(a.credID),
		"type":  "public-key",
		"response": map[string]string{
			"authenticatorData": b64u(authData),
			"clientDataJSON":    b64u(clientData),
			"signature":         b64u(sig),
			"userHandle":        b64u([]byte(strconv.Itoa(userID))),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return resp
}
