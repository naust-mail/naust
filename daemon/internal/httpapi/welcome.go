package httpapi

import (
	"embed"
	htmltemplate "html/template"
	"mime/multipart"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
	texttemplate "text/template"
	"time"
)

// The welcome mail's content lives in templates, not code: the prose
// and layout are editable (and one day brandable) without touching
// the delivery logic. Both variants render from the same data; the
// message is sent as multipart/alternative so text-only clients get
// the plain version.
//
//go:embed templates/welcome.txt.tmpl templates/welcome.html.tmpl
var welcomeFS embed.FS

var (
	welcomeText = texttemplate.Must(texttemplate.ParseFS(welcomeFS, "templates/welcome.txt.tmpl"))
	welcomeHTML = htmltemplate.Must(htmltemplate.ParseFS(welcomeFS, "templates/welcome.html.tmpl"))
)

type welcomeData struct {
	Hostname   string
	AdminURL   string
	WebmailURL string
	Key        string
}

// sendWelcome delivers the first-run welcome message to the new
// admin's own mailbox: the panel and webmail links, and the backup
// recovery key - so the key sits cached in every mail client the
// admin ever connects, instead of only on the box it protects.
// Purely informational: nothing gates on it, and it does not count as
// the key leaving the box (the mailbox dies with the disk), so the
// backup check's "key never saved" step is cleared only by the
// restore-sheet download.
//
// Runs in the background with retries: mail routing for the address
// created moments ago converges once the materializer has run.
func (s *Server) sendWelcome(email string) {
	if s.SubmitAddr == "" {
		return
	}
	delay := s.WelcomeRetryDelay
	if delay == 0 {
		delay = 15 * time.Second
	}
	msg, err := s.welcomeMessage(email)
	if err != nil {
		s.Log.Printf("welcome mail: %v", err)
		return
	}
	go func() {
		for attempt := 0; attempt < 5; attempt++ {
			if attempt > 0 {
				time.Sleep(delay)
			}
			if err = submitMessage(s.SubmitAddr, email, msg); err == nil {
				s.Log.Printf("welcome mail delivered to %s", email)
				return
			}
		}
		s.Log.Printf("welcome mail to %s failed: %v", email, err)
	}()
}

// welcomeMessage renders the multipart/alternative message.
func (s *Server) welcomeMessage(email string) (string, error) {
	data := welcomeData{
		Hostname:   s.PrimaryHostname,
		AdminURL:   "https://" + s.PrimaryHostname + "/admin",
		WebmailURL: "https://" + s.PrimaryHostname + "/mail",
		Key:        s.backupKey(),
	}
	var text, html strings.Builder
	if err := welcomeText.Execute(&text, data); err != nil {
		return "", err
	}
	if err := welcomeHTML.Execute(&html, data); err != nil {
		return "", err
	}

	var body strings.Builder
	mp := multipart.NewWriter(&body)
	for _, part := range []struct{ ctype, content string }{
		{"text/plain; charset=utf-8", text.String()},
		{"text/html; charset=utf-8", html.String()},
	} {
		w, err := mp.CreatePart(textproto.MIMEHeader{"Content-Type": {part.ctype}})
		if err != nil {
			return "", err
		}
		if _, err := w.Write([]byte(part.content)); err != nil {
			return "", err
		}
	}
	if err := mp.Close(); err != nil {
		return "", err
	}

	headers := strings.Join([]string{
		"From: " + s.PrimaryHostname + " <" + email + ">",
		"To: <" + email + ">",
		"Subject: Welcome to " + s.PrimaryHostname,
		"Date: " + time.Now().Format(time.RFC1123Z),
		"Auto-Submitted: auto-generated",
		"MIME-Version: 1.0",
		"Content-Type: multipart/alternative; boundary=" + mp.Boundary(),
	}, "\r\n")
	return headers + "\r\n\r\n" + body.String(), nil
}

// backupKey reads the backup encryption secret, "" when the box has
// none (the welcome mail then simply omits that section).
func (s *Server) backupKey() string {
	data, err := os.ReadFile(filepath.Join(s.StorageRoot, "backup", "secret_key.txt"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}
