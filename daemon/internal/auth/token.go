package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"time"

	"naust/daemon/internal/store/ent"
	entapitoken "naust/daemon/internal/store/ent/apitoken"
)

// API tokens are "naust_" + 256 bits of hex. Like sessions, only the
// SHA-256 of the secret is stored; the plaintext is returned once at
// creation. A deterministic hash gives an O(1) indexed lookup, and a
// 256-bit random secret needs no slow hashing or pepper - guessing is
// infeasible regardless.

const TokenPrefix = "naust_"

// NewAPIToken creates a token for u and returns the plaintext once.
func NewAPIToken(ctx context.Context, client *ent.Client, u *ent.User, name string, scope entapitoken.Scope) (string, *ent.APIToken, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, err
	}
	secret := hex.EncodeToString(raw)
	row, err := client.APIToken.Create().
		SetUser(u).
		SetName(name).
		SetScope(scope).
		SetTokenHash(hashToken(secret)).
		Save(ctx)
	if err != nil {
		return "", nil, err
	}
	return TokenPrefix + secret, row, nil
}

// UserForAPIToken resolves a plaintext bearer token to its row and
// owner. Returns (nil, nil, nil) for unknown or malformed tokens.
// last_used updates at most once a minute so automation traffic does
// not write the database on every request.
func UserForAPIToken(ctx context.Context, client *ent.Client, plaintext string) (*ent.APIToken, *ent.User, error) {
	secret, ok := strings.CutPrefix(plaintext, TokenPrefix)
	if !ok || secret == "" {
		return nil, nil, nil
	}
	row, err := client.APIToken.Query().
		Where(entapitoken.TokenHash(hashToken(secret))).
		WithUser().
		Only(ctx)
	if ent.IsNotFound(err) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	owner, err := row.Edges.UserOrErr()
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	if row.LastUsed == nil || now.Sub(*row.LastUsed) > time.Minute {
		// Best effort; a failed timestamp update must not fail auth.
		_ = client.APIToken.UpdateOne(row).SetLastUsed(now).Exec(ctx)
	}
	return row, owner, nil
}
