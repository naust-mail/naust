package httpapi

import (
	"bufio"
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"naust/daemon/internal/api"
)

// fakeSMTP accepts one delivery and captures the DATA payload.
func fakeSMTP(t *testing.T) (addr string, got chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	got = make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		br := bufio.NewReader(conn)
		reply := func(s string) { conn.Write([]byte(s + "\r\n")) }
		reply("220 test ESMTP")
		var data strings.Builder
		inData := false
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimRight(line, "\r\n")
			if inData {
				if line == "." {
					reply("250 ok")
					got <- data.String()
					inData = false
					continue
				}
				data.WriteString(line + "\n")
				continue
			}
			switch {
			case strings.HasPrefix(line, "EHLO"), strings.HasPrefix(line, "HELO"):
				reply("250 test")
			case strings.HasPrefix(line, "DATA"):
				reply("354 go")
				inData = true
			case strings.HasPrefix(line, "QUIT"):
				reply("221 bye")
				return
			default:
				reply("250 ok")
			}
		}
	}()
	return ln.Addr().String(), got
}

func TestBootstrapSendsWelcome(t *testing.T) {
	s, _ := newTestServer(t)
	// Fresh box: remove the fixture admin so bootstrap is allowed.
	s.Store.User.Delete().ExecX(context.Background())

	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "backup"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "backup", "secret_key.txt"), []byte("KEY-MATERIAL-12345\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s.StorageRoot = root
	addr, got := fakeSMTP(t)
	s.SubmitAddr = addr
	s.WelcomeRetryDelay = 10 * time.Millisecond

	armBootstrap(t, s, "TESTCODE")
	w := doJSON(t, s, "POST", "/api/bootstrap", "", api.BootstrapRequest{
		Code: "TESTCODE", Email: "owner@example.com", Password: "correct horse battery staple",
	})
	if w.Code != 201 {
		t.Fatalf("bootstrap = %d %s", w.Code, w.Body)
	}

	select {
	case msg := <-got:
		for _, want := range []string{
			"To: <owner@example.com>",
			"Subject: Welcome to box.example.com",
			"Content-Type: multipart/alternative",
			"Content-Type: text/plain; charset=utf-8",
			"Content-Type: text/html; charset=utf-8",
			"https://box.example.com/admin",
			"BACKUP RECOVERY KEY",
			"backup recovery key", // HTML variant heading
			"KEY-MATERIAL-12345",
		} {
			if !strings.Contains(msg, want) {
				t.Errorf("welcome mail missing %q:\n%s", want, msg)
			}
		}
		// The key must appear in both parts.
		if strings.Count(msg, "KEY-MATERIAL-12345") != 2 {
			t.Errorf("key not in both parts:\n%s", msg)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("welcome mail never delivered")
	}
}

func TestWelcomeMessageWithoutKey(t *testing.T) {
	s, _ := newTestServer(t)
	s.StorageRoot = t.TempDir() // no secret_key.txt
	msg, err := s.welcomeMessage("owner@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(msg, "RECOVERY KEY") || strings.Contains(msg, "recovery key") {
		t.Errorf("keyless box must omit the key section:\n%s", msg)
	}
	if !strings.Contains(msg, "Webmail") {
		t.Errorf("links missing:\n%s", msg)
	}
}
