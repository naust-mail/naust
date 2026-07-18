package helper

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sort"
	"strings"
	"syscall"
	"time"
)

const (
	// maxRequestLine caps the raw request line. Content args are capped
	// at 1MB after decoding; 4MB leaves room for JSON escaping.
	maxRequestLine = 4 << 20
	readTimeout    = 30 * time.Second
)

// Server accepts one connection at a time and executes one request per
// connection. Serial on purpose: privileged operations must not race
// each other, and the caller is a single manager process.
type Server struct {
	Deps Deps
	// AllowUID restricts callers to one peer UID when >= 0. Socket file
	// permissions are the primary gate; this is defense in depth.
	AllowUID int
	Log      *log.Logger
}

func (s *Server) Serve(l net.Listener) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		s.handle(conn)
	}
}

func (s *Server) handle(conn net.Conn) {
	defer conn.Close()
	start := time.Now()
	conn.SetDeadline(time.Now().Add(readTimeout))

	uid, err := peerUID(conn)
	if err != nil {
		s.audit("-", nil, -1, start, fmt.Errorf("peer credentials: %w", err))
		return
	}
	if s.AllowUID >= 0 && uid != s.AllowUID {
		s.respond(conn, Response{OK: false, Error: "caller uid not permitted"})
		s.audit("-", nil, uid, start, errors.New("uid rejected"))
		return
	}

	line, err := bufio.NewReaderSize(io.LimitReader(conn, maxRequestLine), 64<<10).ReadBytes('\n')
	if err != nil {
		s.respond(conn, Response{OK: false, Error: "request must be one JSON line under 4MB"})
		s.audit("-", nil, uid, start, fmt.Errorf("read: %w", err))
		return
	}
	var req Request
	if err := json.Unmarshal(line, &req); err != nil {
		s.respond(conn, Response{OK: false, Error: "malformed JSON request"})
		s.audit("-", nil, uid, start, fmt.Errorf("decode: %w", err))
		return
	}

	// Execution may legitimately outlast the read deadline (apt).
	conn.SetDeadline(time.Time{})
	result, execErr := Dispatch(context.Background(), s.Deps, req)

	conn.SetDeadline(time.Now().Add(readTimeout))
	if execErr != nil {
		s.respond(conn, Response{OK: false, Error: execErr.Error()})
	} else {
		s.respond(conn, Response{OK: true, Result: result})
	}
	s.audit(req.Intent, req.Args, uid, start, execErr)
}

func (s *Server) respond(conn net.Conn, resp Response) {
	buf, err := json.Marshal(resp)
	if err != nil {
		return
	}
	conn.Write(append(buf, '\n'))
}

// audit writes one line per request with secret args redacted.
func (s *Server) audit(intent string, args map[string]string, uid int, start time.Time, err error) {
	if s.Log == nil {
		return
	}
	outcome := "ok"
	if err != nil {
		outcome = "error: " + err.Error()
	}
	s.Log.Printf("intent=%s args={%s} uid=%d dur=%s %s",
		intent, redactedArgs(intent, args), uid, time.Since(start).Round(time.Millisecond), outcome)
}

func redactedArgs(intent string, args map[string]string) string {
	def := Intents[intent]
	keys := make([]string, 0, len(args))
	for k := range args {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		v := args[k]
		if def.redact[k] {
			v = "[redacted]"
		} else if len(v) > 200 {
			v = v[:200] + "..."
		}
		parts = append(parts, k+"="+v)
	}
	return strings.Join(parts, " ")
}

// peerUID reads SO_PEERCRED from a Unix socket connection.
func peerUID(conn net.Conn) (int, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return -1, errors.New("not a unix socket")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return -1, err
	}
	var cred *syscall.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return -1, err
	}
	if credErr != nil {
		return -1, credErr
	}
	return int(cred.Uid), nil
}
