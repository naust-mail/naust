package helper

import (
	"bufio"
	"encoding/json"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// startServer runs a Server on a temp socket and returns the socket path.
func startServer(t *testing.T, run Runner) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "helper.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &Server{
		Deps:     Deps{Run: run},
		AllowUID: os.Getuid(),
		Log:      log.New(&strings.Builder{}, "", 0),
	}
	go srv.Serve(l)
	t.Cleanup(func() { l.Close() })
	return sock
}

// roundTrip sends one raw line and returns the decoded response.
func roundTrip(t *testing.T, sock, line string) Response {
	t.Helper()
	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// A rejecting server may respond and close before our write lands
	// (seen as EPIPE under parallel test load); the response is still
	// in the socket buffer, so read regardless.
	if _, err := conn.Write([]byte(line)); err != nil {
		t.Logf("write raced with server close: %v", err)
	}
	raw, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		t.Fatal(err)
	}
	var resp Response
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("bad response %q: %v", raw, err)
	}
	return resp
}

func TestSocketRoundTrip(t *testing.T) {
	run := &fakeRunner{}
	sock := startServer(t, run)

	req, _ := json.Marshal(Request{Intent: "service.reload", Args: map[string]string{"service": "nginx"}})
	resp := roundTrip(t, sock, string(req)+"\n")
	if !resp.OK {
		t.Fatalf("want ok, got error %q", resp.Error)
	}
	if len(run.calls) != 1 || run.calls[0][2] != "nginx" {
		t.Fatalf("unexpected calls %v", run.calls)
	}
}

func TestSocketRejectsUnknownIntent(t *testing.T) {
	run := &fakeRunner{}
	sock := startServer(t, run)

	req, _ := json.Marshal(Request{Intent: "shell.exec", Args: map[string]string{"cmd": "id"}})
	resp := roundTrip(t, sock, string(req)+"\n")
	if resp.OK || !strings.Contains(resp.Error, "unknown intent") {
		t.Fatalf("want unknown-intent error, got %+v", resp)
	}
	if len(run.calls) != 0 {
		t.Fatalf("nothing must execute, ran %v", run.calls)
	}
}

func TestSocketRejectsMalformedJSON(t *testing.T) {
	sock := startServer(t, &fakeRunner{})

	resp := roundTrip(t, sock, "service.reload nginx\n")
	if resp.OK || !strings.Contains(resp.Error, "malformed") {
		t.Fatalf("want malformed-JSON error, got %+v", resp)
	}
}

func TestSocketReportsExecutionFailure(t *testing.T) {
	run := &fakeRunner{failOn: map[string]error{"systemctl": os.ErrPermission}}
	sock := startServer(t, run)

	req, _ := json.Marshal(Request{Intent: "service.restart", Args: map[string]string{"service": "dovecot"}})
	resp := roundTrip(t, sock, string(req)+"\n")
	if resp.OK || !strings.Contains(resp.Error, "permission") {
		t.Fatalf("want permission error surfaced, got %+v", resp)
	}
}

// TestSocketRejectsOversizedRequestLine proves a request line over
// maxRequestLine is rejected cleanly (bounded error, connection
// closed) rather than the server hanging forever waiting for a
// newline that will never come, or panicking trying to buffer it all.
func TestSocketRejectsOversizedRequestLine(t *testing.T) {
	sock := startServer(t, &fakeRunner{})

	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	oversized := make([]byte, maxRequestLine+1024) // no trailing newline
	for i := range oversized {
		oversized[i] = 'a'
	}
	go func() {
		if _, err := conn.Write(oversized); err != nil {
			t.Logf("write raced with server close: %v", err)
		}
	}()

	raw, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		t.Fatalf("server never responded to the oversized line: %v", err)
	}
	var resp Response
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("bad response %q: %v", raw, err)
	}
	if resp.OK || !strings.Contains(resp.Error, "4MB") {
		t.Fatalf("want a bounded oversized-request error, got %+v", resp)
	}
}

// TestPeerUIDRejectsNonUnixConn proves a connection that is not a
// *net.UnixConn (SO_PEERCRED only exists on unix sockets) is rejected
// outright rather than falling through to some default uid that would
// bypass the AllowUID gate.
func TestPeerUIDRejectsNonUnixConn(t *testing.T) {
	client, srv := net.Pipe()
	defer client.Close()
	defer srv.Close()

	if _, err := peerUID(srv); err == nil {
		t.Fatal("non-unix-socket connection silently accepted for peer credentials")
	}
}

func TestSocketRejectsWrongUID(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "helper.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	srv := &Server{
		Deps:     Deps{Run: &fakeRunner{}},
		AllowUID: os.Getuid() + 1, // deliberately not us
		Log:      log.New(&strings.Builder{}, "", 0),
	}
	go srv.Serve(l)

	req, _ := json.Marshal(Request{Intent: "host.reboot"})
	resp := roundTrip(t, sock, string(req)+"\n")
	if resp.OK || !strings.Contains(resp.Error, "uid") {
		t.Fatalf("want uid rejection, got %+v", resp)
	}
}
