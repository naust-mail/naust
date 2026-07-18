// Package boxconf reads the box configuration written by setup:
// /etc/naust.conf, shell-sourceable KEY=value lines, with values
// either single-quoted by the boxctl wizard or bare. Real environment
// variables take precedence over the file - that is the Docker path,
// where compose supplies the same variable names and no conf file
// exists. The resulting lookup is what registry.Enabled and the web
// renderer consume; a setup re-run that changes choices is picked up on
// daemon restart, which setup performs anyway.
package boxconf

import (
	"bufio"
	"os"
	"strings"
)

// Conf is the parsed file contents. Get layers the process environment
// on top, so an empty Conf is usable (env-only, the Docker case).
type Conf map[string]string

// Load parses the conf file. A missing file is not an error: Docker
// boxes configure through the environment alone.
func Load(path string) (Conf, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return Conf{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()

	c := Conf{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, rest, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		// First occurrence wins, matching the Python loader.
		if _, dup := c[k]; !dup && k != "" {
			c[k] = unquote(rest)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return c, nil
}

// Get returns the value for key: process environment first, then the
// file, else "".
func (c Conf) Get(key string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return c[key]
}

// unquote takes the first shell token of a value, mirroring the Python
// loader's shlex.split(rest)[0]: single quotes with the quote-backslash-quote-quote escape
// (what the wizard writes), simple double quotes, or a bare token cut
// at whitespace (what save_environment writes).
func unquote(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	switch s[0] {
	case '\'':
		var b strings.Builder
		rest := s[1:]
		for {
			i := strings.IndexByte(rest, '\'')
			if i < 0 {
				b.WriteString(rest) // unterminated; take what's there
				break
			}
			b.WriteString(rest[:i])
			rest = rest[i+1:]
			// '\'' embeds a literal quote and reopens the string.
			if strings.HasPrefix(rest, `\''`) {
				b.WriteByte('\'')
				rest = rest[3:]
				continue
			}
			break
		}
		return b.String()
	case '"':
		if i := strings.IndexByte(s[1:], '"'); i >= 0 {
			return s[1 : 1+i]
		}
		return s[1:]
	default:
		if i := strings.IndexAny(s, " \t"); i >= 0 {
			return s[:i]
		}
		return s
	}
}
