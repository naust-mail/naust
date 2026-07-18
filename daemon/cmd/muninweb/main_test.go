package main

import (
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestHandlerServesStaticSite(t *testing.T) {
	www := t.TempDir()
	if err := os.WriteFile(filepath.Join(www, "index.html"), []byte("<html>munin</html>"), 0o644); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(handler(www, "/nonexistent"))
	defer srv.Close()

	resp, err := srv.Client().Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || string(body) != "<html>munin</html>" {
		t.Fatalf("static: got %d %q", resp.StatusCode, body)
	}
}

func TestHandlerExecutesGraphCGI(t *testing.T) {
	// A stub in place of munin-cgi-graph proves the CGI plumbing:
	// exec, header pass-through, and PATH_INFO carrying the graph
	// path exactly as dynazoom requests it.
	stub := filepath.Join(t.TempDir(), "graph.sh")
	script := "#!/bin/sh\n" +
		"printf 'Content-Type: image/png\\r\\n'\n" +
		"printf '\\r\\n'\n" +
		"printf 'PNG:%s' \"$PATH_INFO\"\n"
	if err := os.WriteFile(stub, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(handler(t.TempDir(), stub))
	defer srv.Close()

	resp, err := srv.Client().Get(srv.URL + "/cgi-graph/box.example.com/cpu-day.png")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("cgi: got %d %q", resp.StatusCode, body)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "image/png" {
		t.Fatalf("cgi content-type: got %q", ct)
	}
	if string(body) != "PNG:/box.example.com/cpu-day.png" {
		t.Fatalf("cgi PATH_INFO: got %q", body)
	}
}
