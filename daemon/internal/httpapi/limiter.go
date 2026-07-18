package httpapi

import (
	"context"
	"time"

	entauthfailure "naust/daemon/internal/store/ent/authfailure"
)

// Sliding-window rate limits, keyed by email because the store is the
// only thing shared across restarts and replicas - and for the verify
// endpoint the caller is always loopback, so IPs cannot distinguish an
// attacker from a stale mail client. Each kind is its own window.
const (
	failureKindRelink = "relink"
	failureKindVerify = "verify"
)

// authFailuresExceeded reports whether the email has burned its
// attempts for kind inside the window.
func (s *Server) authFailuresExceeded(ctx context.Context, kind, email string, maxFailures int, window time.Duration) (bool, error) {
	n, err := s.Store.AuthFailure.Query().
		Where(
			entauthfailure.Kind(kind),
			entauthfailure.Email(email),
			entauthfailure.AtGT(time.Now().Add(-window)),
		).
		Count(ctx)
	return n >= maxFailures, err
}

// recordAuthFailure adds one failure and prunes rows of the same kind
// outside the window. Best-effort: the failure is already in the
// auth-failure log and counter, so a write error only softens the
// rate limit.
func (s *Server) recordAuthFailure(ctx context.Context, kind, email string, window time.Duration) {
	if _, err := s.Store.AuthFailure.Delete().
		Where(
			entauthfailure.Kind(kind),
			entauthfailure.AtLTE(time.Now().Add(-window)),
		).
		Exec(ctx); err != nil {
		s.Log.Printf("%s limiter: prune: %v", kind, err)
	}
	if err := s.Store.AuthFailure.Create().
		SetKind(kind).
		SetEmail(email).
		Exec(ctx); err != nil {
		s.Log.Printf("%s limiter: record: %v", kind, err)
	}
}

// clearAuthFailures resets the window after a success.
func (s *Server) clearAuthFailures(ctx context.Context, kind, email string) {
	if _, err := s.Store.AuthFailure.Delete().
		Where(
			entauthfailure.Kind(kind),
			entauthfailure.Email(email),
		).
		Exec(ctx); err != nil {
		s.Log.Printf("%s limiter: clear: %v", kind, err)
	}
}
