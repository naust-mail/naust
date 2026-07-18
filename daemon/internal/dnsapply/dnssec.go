package dnsapply

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// DNSSEC signing keys live in a directory of .conf files (one per
// algorithm, written at setup), each naming a KSK and ZSK key file
// base. Key files are generated against the placeholder domain
// "_domain_" and patched to the real domain before signing.

type signingKey struct {
	keyType string // "KSK" or "ZSK"
	base    string // key filename base, no extension
}

// findSigningKeys reads every .conf in dir and returns the keys that
// apply to domain. A conf may limit itself with DOMAINS=a,b; an empty
// or absent DOMAINS means all domains.
func findSigningKeys(dir, domain string) ([]signingKey, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var keys []signingKey
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".conf") {
			continue
		}
		conf, err := parseEnvFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		if domains, ok := conf["DOMAINS"]; ok && !containsDomain(domains, domain) {
			continue
		}
		for _, kt := range []string{"KSK", "ZSK"} {
			base, ok := conf[kt]
			if !ok {
				return nil, fmt.Errorf("%s: missing %s", e.Name(), kt)
			}
			keys = append(keys, signingKey{kt, base})
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].keyType != keys[j].keyType {
			return keys[i].keyType < keys[j].keyType
		}
		return keys[i].base < keys[j].base
	})
	return keys, nil
}

func containsDomain(list, domain string) bool {
	for _, d := range strings.Split(list, ",") {
		if strings.TrimSpace(d) == domain {
			return true
		}
	}
	return false
}

// parseEnvFile reads KEY=VALUE lines; blank lines and #-comments skip.
func parseEnvFile(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	vars := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			vars[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return vars, nil
}

// keysHash fingerprints the private keys that would sign domain, so a
// key rotation changes the zone hash and forces a re-sign. Returns
// "unsigned" when the key directory is absent or holds no keys for the
// domain: the fingerprint still differs from every signed state.
func keysHash(dir, domain string) (string, error) {
	keys, err := findSigningKeys(dir, domain)
	if os.IsNotExist(err) {
		return "unsigned", nil
	}
	if err != nil {
		return "", err
	}
	if len(keys) == 0 {
		return "unsigned", nil
	}
	h := sha256.New()
	for _, k := range keys {
		data, err := os.ReadFile(filepath.Join(dir, k.base+".private"))
		if err != nil {
			return "", err
		}
		fmt.Fprintf(h, "%s\x00%s\x00", k.keyType, k.base)
		h.Write(data)
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// patchKeys copies domain's key files into tmpDir with the placeholder
// domain replaced, returning the patched key file bases (all of them,
// and the key-signing subset for DS generation).
func patchKeys(dir, domain, tmpDir string) (all, ksks []string, err error) {
	keys, err := findSigningKeys(dir, domain)
	if err != nil {
		return nil, nil, err
	}
	for _, k := range keys {
		patchedBase := filepath.Join(tmpDir, strings.ReplaceAll(k.base, "_domain_", domain))
		for _, ext := range []string{".private", ".key"} {
			data, err := os.ReadFile(filepath.Join(dir, k.base+ext))
			if err != nil {
				return nil, nil, err
			}
			patched := strings.ReplaceAll(string(data), "_domain_", domain)
			if err := os.WriteFile(patchedBase+ext, []byte(patched), 0o600); err != nil {
				return nil, nil, err
			}
		}
		all = append(all, patchedBase)
		if k.keyType == "KSK" {
			ksks = append(ksks, patchedBase)
		}
	}
	return all, ksks, nil
}
