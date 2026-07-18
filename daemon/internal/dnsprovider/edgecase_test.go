package dnsprovider

// These tests document the current, intentionally minimal error
// handling of doJSON and the three provider clients: a non-2xx
// response (429 rate limit, 5xx, or otherwise) becomes a single plain
// error with no retry, no backoff, and no Retry-After handling. There
// is no retry loop anywhere above these clients either (acmeprov.DNS01
// calls SetTXT/DeleteTXT once per challenge). If that ever needs to
// change, these tests are the place that would need updating.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// countingHandler wraps h and counts how many requests actually
// reached the server, so tests can prove a failure was not retried.
func countingHandler(h http.HandlerFunc) (http.HandlerFunc, *int32) {
	var n int32
	return func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&n, 1)
		h(w, r)
	}, &n
}

func TestDoJSONRateLimitedIsNotRetried(t *testing.T) {
	handler, calls := countingHandler(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprint(w, `{"error":"rate limited"}`)
	})
	srv := httptest.NewServer(handler)
	defer srv.Close()

	err := doJSON(context.Background(), srv.Client(), http.MethodGet, srv.URL, nil, nil, nil)
	if err == nil {
		t.Fatal("expected error on 429")
	}
	if !strings.Contains(err.Error(), "429") {
		t.Errorf("error does not mention status: %v", err)
	}
	if got := atomic.LoadInt32(calls); got != 1 {
		t.Errorf("calls = %d, want exactly 1 (no retry on rate limit)", got)
	}
}

func TestDoJSON5xxIsNotRetried(t *testing.T) {
	handler, calls := countingHandler(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "upstream exploded", http.StatusBadGateway)
	})
	srv := httptest.NewServer(handler)
	defer srv.Close()

	err := doJSON(context.Background(), srv.Client(), http.MethodGet, srv.URL, nil, nil, nil)
	if err == nil {
		t.Fatal("expected error on 502")
	}
	if got := atomic.LoadInt32(calls); got != 1 {
		t.Errorf("calls = %d, want exactly 1 (no retry on 5xx)", got)
	}
}

func TestDoJSONTruncatesLongErrorBody(t *testing.T) {
	long := strings.Repeat("x", 500)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, long, http.StatusBadRequest)
	}))
	defer srv.Close()

	err := doJSON(context.Background(), srv.Client(), http.MethodGet, srv.URL, nil, nil, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if len(err.Error()) > 300 {
		t.Errorf("error body not truncated: %d chars", len(err.Error()))
	}
}

func TestDoJSONMalformedBodyOn2xxErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `not json`)
	}))
	defer srv.Close()

	var out struct{ X string }
	err := doJSON(context.Background(), srv.Client(), http.MethodGet, srv.URL, nil, nil, &out)
	if err == nil {
		t.Fatal("expected unmarshal error on malformed JSON body")
	}
}

func TestDoJSONHonorsContextCancellation(t *testing.T) {
	handler, calls := countingHandler(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{}`)
	})
	srv := httptest.NewServer(handler)
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := doJSON(ctx, srv.Client(), http.MethodGet, srv.URL, nil, nil, nil)
	if err == nil {
		t.Fatal("expected error for a cancelled context")
	}
	if got := atomic.LoadInt32(calls); got != 0 {
		t.Errorf("calls = %d, want 0 (cancelled before the request was sent)", got)
	}
}

func TestHetznerZoneNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"zones":[]}`)
	}))
	defer srv.Close()

	hz := &Hetzner{Token: "t", HTTP: srv.Client(), BaseURL: srv.URL}
	if err := hz.SetTXT(context.Background(), "example.com", "_acme-challenge.example.com", "val"); err == nil {
		t.Error("unknown zone accepted")
	}
}

func TestDigitalOceanRateLimitedOnCreateSurfacesSingleError(t *testing.T) {
	handler, calls := countingHandler(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprint(w, `{"message":"too many requests"}`)
	})
	srv := httptest.NewServer(handler)
	defer srv.Close()

	do := &DigitalOcean{Token: "t", HTTP: srv.Client(), BaseURL: srv.URL}
	err := do.SetTXT(context.Background(), "example.com", "_acme-challenge.mail.example.com", "val")
	if err == nil {
		t.Fatal("expected error on 429")
	}
	if got := atomic.LoadInt32(calls); got != 1 {
		t.Errorf("calls = %d, want exactly 1 (no retry on rate limit)", got)
	}
}

func TestDigitalOceanDomainNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"message":"domain not found"}`)
	}))
	defer srv.Close()

	do := &DigitalOcean{Token: "t", HTTP: srv.Client(), BaseURL: srv.URL}
	if err := do.SetTXT(context.Background(), "nope.example", "_acme-challenge.nope.example", "val"); err == nil {
		t.Error("unknown domain accepted")
	}
}

// TestCleanupWithNoMatchingRecordIsANoOp covers the case where the
// challenge TXT record was already removed (e.g. a retried Cleanup
// after a prior partial failure): zero matches must not error and
// must not attempt any delete call.
func TestCleanupWithNoMatchingRecordIsANoOp(t *testing.T) {
	deleteCalls := int32(0)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/domains/example.com/records" && r.Method == http.MethodGet:
			fmt.Fprint(w, `{"domain_records":[]}`)
		case r.Method == http.MethodDelete:
			atomic.AddInt32(&deleteCalls, 1)
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected call %s %s", r.Method, r.URL)
		}
	}))
	defer srv.Close()

	do := &DigitalOcean{Token: "t", HTTP: srv.Client(), BaseURL: srv.URL}
	if err := do.DeleteTXT(context.Background(), "example.com", "_acme-challenge.mail.example.com", "val"); err != nil {
		t.Fatalf("DeleteTXT with no match: %v", err)
	}
	if got := atomic.LoadInt32(&deleteCalls); got != 0 {
		t.Errorf("delete calls = %d, want 0", got)
	}
}

// TestCleanupStopsOnFirstDeleteFailure documents that when more than
// one TXT record matches (e.g. a concurrent order racing this one),
// a mid-loop delete failure - such as a 429 - aborts the rest of the
// batch rather than continuing best-effort. Some records this box
// published can be left behind until Cleanup is retried.
func TestCleanupStopsOnFirstDeleteFailure(t *testing.T) {
	var deletePaths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/zones" && r.Method == http.MethodGet:
			fmt.Fprint(w, `{"zones":[{"id":"hz1"}]}`)
		case r.URL.Path == "/records" && r.Method == http.MethodGet:
			fmt.Fprint(w, `{"records":[
				{"id":"a","type":"TXT","name":"_acme-challenge.mail","value":"val"},
				{"id":"b","type":"TXT","name":"_acme-challenge.mail","value":"val"}]}`)
		case strings.HasPrefix(r.URL.Path, "/records/") && r.Method == http.MethodDelete:
			deletePaths = append(deletePaths, r.URL.Path)
			w.WriteHeader(http.StatusTooManyRequests)
			fmt.Fprint(w, `{"error":"rate limited"}`)
		default:
			t.Errorf("unexpected call %s %s", r.Method, r.URL)
		}
	}))
	defer srv.Close()

	hz := &Hetzner{Token: "t", HTTP: srv.Client(), BaseURL: srv.URL}
	err := hz.DeleteTXT(context.Background(), "example.com", "_acme-challenge.mail.example.com", "val")
	if err == nil {
		t.Fatal("expected the first delete's 429 to surface as an error")
	}
	if len(deletePaths) != 1 {
		t.Errorf("delete attempts = %v, want exactly 1 (loop stops on first failure, second record left behind)", deletePaths)
	}
}
