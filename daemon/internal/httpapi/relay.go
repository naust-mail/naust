package httpapi

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/smtp"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"naust/daemon/internal/api"
	"naust/daemon/internal/store/ent"
	entsetting "naust/daemon/internal/store/ent/setting"
)

// settingSMTPRelay holds the relay configuration as a JSON
// relaySettings value. dnsapply reads the same row for spf_include
// when building zone SPF records.
const settingSMTPRelay = "smtp_relay"

// relaySettings is the persisted shape of the smtp_relay setting. The
// password is deliberately absent: it lives only in the Postfix lookup
// table under RelayDir.
type relaySettings struct {
	Host       string `json:"host"`
	Port       int    `json:"port"`
	User       string `json:"user"`
	SPFInclude string `json:"spf_include"`
}

// relayHostRe is strict on purpose: these values reach postconf -e and
// the SASL credential file, so newlines and shell-ish characters must
// never pass.
var relayHostRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-.]{0,251}[a-zA-Z0-9])?$`)

func (s *Server) relaySettings(r *http.Request) (*relaySettings, error) {
	row, err := s.Store.Setting.Query().
		Where(entsetting.Key(settingSMTPRelay)).
		Only(r.Context())
	if ent.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var cfg relaySettings
	if err := json.Unmarshal([]byte(row.Value), &cfg); err != nil {
		return nil, fmt.Errorf("%s setting: %w", settingSMTPRelay, err)
	}
	return &cfg, nil
}

func (s *Server) relayConfig(r *http.Request) (api.RelayConfig, error) {
	resp := api.RelayConfig{Port: 587}
	cfg, err := s.relaySettings(r)
	if err != nil {
		return resp, err
	}
	if cfg != nil {
		resp.Host, resp.Port, resp.User, resp.SPFInclude = cfg.Host, cfg.Port, cfg.User, cfg.SPFInclude
	}
	_, statErr := os.Stat(filepath.Join(s.RelayDir, "sasl_passwd.db"))
	resp.PasswordSet = statErr == nil
	return resp, nil
}

func (s *Server) handleRelayGet(w http.ResponseWriter, r *http.Request) {
	resp, err := s.relayConfig(r)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "relay config lookup failed")
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleRelaySet(w http.ResponseWriter, r *http.Request) {
	var req api.SetRelayRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if req.Host != "" {
		if !relayHostRe.MatchString(req.Host) {
			writeError(w, http.StatusBadRequest, "invalid relay host")
			return
		}
		if req.Port == 0 {
			req.Port = 587
		}
		if req.Port < 1 || req.Port > 65535 {
			writeError(w, http.StatusBadRequest, "invalid port number")
			return
		}
	}
	if req.SPFInclude != "" && !relayHostRe.MatchString(req.SPFInclude) {
		writeError(w, http.StatusBadRequest, "invalid SPF include hostname")
		return
	}
	if strings.ContainsAny(req.User+req.Password, "\r\n") {
		writeError(w, http.StatusBadRequest, "relay username and password may not contain newlines")
		return
	}

	// Apply to Postfix before persisting, so a failure leaves the
	// stored configuration matching what Postfix actually runs.
	if err := s.applyRelay(r, req); err != nil {
		writeError(w, http.StatusInternalServerError, "applying relay config failed: "+err.Error())
		return
	}

	if req.Host == "" {
		_, err := s.Store.Setting.Delete().
			Where(entsetting.Key(settingSMTPRelay)).
			Exec(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, "setting update failed")
			return
		}
	} else {
		encoded, err := json.Marshal(relaySettings{
			Host: req.Host, Port: req.Port, User: req.User, SPFInclude: req.SPFInclude,
		})
		if err != nil {
			writeError(w, http.StatusInternalServerError, "setting update failed")
			return
		}
		err = s.Store.Setting.Create().
			SetKey(settingSMTPRelay).
			SetValue(string(encoded)).
			OnConflictColumns(entsetting.FieldKey).
			UpdateNewValues().
			Exec(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, "setting update failed")
			return
		}
	}

	// SPF records change with the relay, so the zones rebuild.
	s.dnsDataChanged()

	resp, err := s.relayConfig(r)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "relay config lookup failed")
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// applyRelay pushes the relay configuration into Postfix: credentials
// into the lookup table under RelayDir (manager-owned, so postmap runs
// unprivileged here), main.cf parameters via helperd postfix.set.
func (s *Server) applyRelay(r *http.Request, req api.SetRelayRequest) error {
	saslPasswd := filepath.Join(s.RelayDir, "sasl_passwd")
	saslDB := saslPasswd + ".db"

	if req.Host == "" {
		for _, kv := range [][2]string{
			{"relayhost", ""},
			{"smtp_sasl_auth_enable", "no"},
			{"smtp_sasl_password_maps", ""},
			{"smtp_sasl_security_options", ""},
			{"smtp_tls_security_level", "dane"},
		} {
			if _, err := s.Helper.Call(r.Context(), "postfix.set", map[string]string{"key": kv[0], "value": kv[1]}); err != nil {
				return err
			}
		}
		os.Remove(saslPasswd)
		os.Remove(saslDB)
		return nil
	}

	if req.Password != "" {
		// The plaintext credential file exists only for the postmap
		// step; only the compiled .db persists. A blank password keeps
		// the existing .db unchanged.
		if err := os.MkdirAll(s.RelayDir, 0o700); err != nil {
			return err
		}
		line := fmt.Sprintf("[%s]:%d %s:%s\n", req.Host, req.Port, req.User, req.Password)
		if err := os.WriteFile(saslPasswd, []byte(line), 0o600); err != nil {
			return err
		}
		defer os.Remove(saslPasswd)
		if err := s.RunPostmap(r.Context(), saslPasswd); err != nil {
			return err
		}
		if err := os.Chmod(saslDB, 0o600); err != nil {
			return err
		}
	}

	for _, kv := range [][2]string{
		{"relayhost", fmt.Sprintf("[%s]:%d", req.Host, req.Port)},
		{"smtp_sasl_auth_enable", "yes"},
		{"smtp_sasl_password_maps", "hash:" + saslPasswd},
		{"smtp_sasl_security_options", "noanonymous"},
		{"smtp_tls_security_level", "verify"},
	} {
		if _, err := s.Helper.Call(r.Context(), "postfix.set", map[string]string{"key": kv[0], "value": kv[1]}); err != nil {
			return err
		}
	}
	return nil
}

// handleRelayTest is a pre-save connectivity probe using the same TLS
// posture Postfix will: implicit TLS on 465, STARTTLS otherwise.
// Nothing is stored and Postfix is untouched.
func (s *Server) handleRelayTest(w http.ResponseWriter, r *http.Request) {
	var req api.RelayTestRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if req.Host == "" {
		writeError(w, http.StatusBadRequest, "no relay host specified")
		return
	}
	if !relayHostRe.MatchString(req.Host) {
		writeError(w, http.StatusBadRequest, "invalid relay host")
		return
	}
	// Allowlist of ports used by known relay providers, so this probe
	// cannot serve as an internal port-scanning oracle.
	switch req.Port {
	case 25, 465, 587, 2525:
	default:
		writeError(w, http.StatusBadRequest, "invalid port number; use 25, 465, 587, or 2525")
		return
	}

	if err := probeRelay(req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	msg := "Connected successfully. Provide a username and password to also verify authentication."
	if req.User != "" && req.Password != "" {
		msg = "Connected and authenticated successfully."
	}
	writeJSON(w, http.StatusOK, api.MessageResponse{Message: msg})
}

func probeRelay(req api.RelayTestRequest) error {
	addr := net.JoinHostPort(req.Host, strconv.Itoa(req.Port))
	dialer := net.Dialer{Timeout: 10 * time.Second}
	tlsConfig := &tls.Config{ServerName: req.Host}

	var client *smtp.Client
	if req.Port == 465 {
		conn, err := tls.DialWithDialer(&dialer, "tcp", addr, tlsConfig)
		if err != nil {
			return fmt.Errorf("connection failed: %w", err)
		}
		client, err = smtp.NewClient(conn, req.Host)
		if err != nil {
			conn.Close()
			return fmt.Errorf("SMTP error: %w", err)
		}
	} else {
		conn, err := dialer.Dial("tcp", addr)
		if err != nil {
			return fmt.Errorf("connection failed: %w", err)
		}
		conn.SetDeadline(time.Now().Add(30 * time.Second))
		client, err = smtp.NewClient(conn, req.Host)
		if err != nil {
			conn.Close()
			return fmt.Errorf("SMTP error: %w", err)
		}
		if err := client.StartTLS(tlsConfig); err != nil {
			client.Close()
			return fmt.Errorf("STARTTLS failed: %w", err)
		}
	}
	defer client.Close()

	if req.User != "" && req.Password != "" {
		if err := client.Auth(smtp.PlainAuth("", req.User, req.Password, req.Host)); err != nil {
			return fmt.Errorf("authentication failed; check the username and password (%w)", err)
		}
	}
	return client.Quit()
}

// handleRelaySendTest submits a real message to Postfix so it routes
// through the configured relay. This catches relay-side rejections
// (unverified sender domain, IP not allowed, DKIM required) that the
// connectivity probe cannot.
func (s *Server) handleRelaySendTest(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.relaySettings(r)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "relay config lookup failed")
		return
	}
	if cfg == nil || cfg.Host == "" {
		writeError(w, http.StatusBadRequest, "no relay is configured; save a relay configuration first")
		return
	}

	addr := s.SubmitAddr
	if addr == "" {
		addr = "localhost:25"
	}
	email := userFrom(r).Email
	msg := strings.Join([]string{
		"From: " + email,
		"To: " + email,
		"Subject: Naust relay test",
		"Date: " + time.Now().Format(time.RFC1123Z),
		"",
		"This is a test email sent through your configured SMTP relay to confirm that outbound mail is working correctly.",
		"",
	}, "\r\n")

	if err := submitMessage(addr, email, msg); err != nil {
		writeError(w, http.StatusBadRequest, "failed to send: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, api.MessageResponse{
		Message: fmt.Sprintf("Test email sent to %s. Check your inbox.", email),
	})
}

// submitMessage hands one message to Postfix over plain SMTP. This is
// the trusted local hop (or the mail container in Docker); deliberately
// no STARTTLS, matching how local services submit mail.
func submitMessage(addr, email, msg string) error {
	conn, err := net.DialTimeout("tcp", addr, 15*time.Second)
	if err != nil {
		return err
	}
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	client, err := smtp.NewClient(conn, "localhost")
	if err != nil {
		conn.Close()
		return err
	}
	defer client.Close()
	if err := client.Mail(email); err != nil {
		return err
	}
	if err := client.Rcpt(email); err != nil {
		return err
	}
	wc, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := wc.Write([]byte(msg)); err != nil {
		wc.Close()
		return err
	}
	if err := wc.Close(); err != nil {
		return err
	}
	return client.Quit()
}
