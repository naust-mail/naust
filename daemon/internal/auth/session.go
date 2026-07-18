package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"naust/daemon/internal/store/ent"
	entsession "naust/daemon/internal/store/ent/session"
)

// DefaultSessionTTL bounds how long a login lasts. Sessions are
// absolute-expiry; there is no sliding renewal yet.
const DefaultSessionTTL = 24 * time.Hour

// NewSession mints a bearer token for u and stores its hash. The
// returned token is the only copy; it cannot be recovered later.
func NewSession(ctx context.Context, client *ent.Client, u *ent.User, ttl time.Duration) (string, time.Time, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", time.Time{}, err
	}
	token := hex.EncodeToString(raw)
	expires := time.Now().Add(ttl)
	_, err := client.Session.Create().
		SetUser(u).
		SetTokenHash(hashToken(token)).
		SetExpiresAt(expires).
		Save(ctx)
	if err != nil {
		return "", time.Time{}, err
	}
	return token, expires, nil
}

// UserForToken resolves a bearer token to its user, or (nil, nil) when
// the token is unknown or expired. Errors are real store failures only.
func UserForToken(ctx context.Context, client *ent.Client, token string) (*ent.User, error) {
	sess, err := client.Session.Query().
		Where(
			entsession.TokenHash(hashToken(token)),
			entsession.ExpiresAtGT(time.Now()),
		).
		WithUser().
		Only(ctx)
	if ent.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	// Best-effort activity timestamp; failure must not block the request.
	_ = sess.Update().SetLastUsed(time.Now()).Exec(ctx)
	return sess.Edges.User, nil
}

// DeleteSession revokes the session belonging to token, if any.
func DeleteSession(ctx context.Context, client *ent.Client, token string) error {
	_, err := client.Session.Delete().
		Where(entsession.TokenHash(hashToken(token))).
		Exec(ctx)
	return err
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
