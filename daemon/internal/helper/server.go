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
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"
)

const (
	// maxRequestLine caps the raw request line. Content args are capped
	// at 1MB after decoding; 4MB leaves room for JSON escaping.
	maxRequestLine = 4 << 20
	readTimeout    = 30 * time.Second

	// maxConns bounds how many connections may be reading at once, so a
	// flood of half-open connections cannot exhaust goroutines. Excess
	// connections wait in the kernel backlog.
	maxConns = 32
)

// Server reads connections concurrently but executes privileged
// operations one at a time (execMu). Concurrency is only for the read
// and handshake so a slow or half-open caller cannot stall the accept
// loop; the execution itself stays serial because privileged operations
// must not race each other.
type Server struct {
	Deps Deps
	// AllowUID restricts callers to one peer UID when >= 0. Socket file
	// permissions are the primary gate; this is defense in depth.
	AllowUID int
	Log      *log.Logger

	// execMu serializes intent execution across concurrent connections.
	execMu sync.Mutex
}

func (s *Server) Serve(l net.Listener) error {
	sem := make(chan struct{}, maxConns)
	for {
		conn, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		sem <- struct{}{}
		go func() {
			defer func() { <-sem }()
			s.handle(conn)
		}()
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

	// Execution may legitimately outlast the read deadline (apt). Hold
	// execMu so privileged operations run one at a time even though reads
	// are concurrent.
	conn.SetDeadline(time.Time{})
	s.execMu.Lock()
	result, execErr := Dispatch(context.Background(), s.Deps, req)
	s.execMu.Unlock()

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
		parts = append(parts, k+"="+sanitizeLogValue(v))
	}
	return strings.Join(parts, " ")
}

// sanitizeLogValue escapes control characters so a caller-supplied arg
// value cannot forge additional audit lines - an embedded newline would
// otherwise let a compromised caller write fake intent records. Values
// with no control characters pass through unchanged.
func sanitizeLogValue(v string) string {
	for _, r := range v {
		if unicode.IsControl(r) {
			return strconv.Quote(v)
		}
	}
	return v
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
