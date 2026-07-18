package checks

import (
	"context"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func notDocker(d *Deps) bool { return !d.InDocker }

func systemChecks() []Check {
	return []Check{
		{
			Name:        "free-disk-space",
			Title:       "Free disk space",
			ShortLabel:  "disk",
			Description: "Watches how full the disk holding your mail is. A full disk stops mail delivery, so this warns well before that point.",
			Class:       ClassMetric,
			Category:    "system", Locus: LocusNode, Tier: TierFast,
			Run: checkFreeDisk,
		},
		{
			Name:        "free-memory",
			Title:       "Free memory",
			ShortLabel:  "memory",
			Description: "Checks how much of the system's memory is still available for use. When memory runs very low the server slows down or starts killing processes, which can interrupt mail handling.",
			Class:       ClassMetric,
			Category:    "system", Locus: LocusNode, Tier: TierFast,
			Run: checkFreeMemory,
		},
		{
			Name:        "software-updates",
			Title:       "Software updates",
			Description: "Confirms all available software updates are installed and that no restart is still waiting to finish an update. Out-of-date software leaves known security holes open, and a pending reboot means an installed update has not fully taken effect.",
			Category:    "system", Locus: LocusNode, Tier: TierDaily,
			Enabled: notDocker, Run: checkSoftwareUpdates,
		},
		{
			Name:        "ssh-password-auth",
			Title:       "SSH password login",
			Description: "Confirms the server's remote login accepts only key-based logins and refuses passwords. Password logins can be guessed by attackers, so keeping them off protects the whole machine.",
			Category:    "system", Locus: LocusNode, Tier: TierDaily,
			Enabled: notDocker, Run: checkSSHPasswordAuth,
		},
		{
			Name:        "time-sync",
			Title:       "Time synchronization",
			Description: "Confirms the system clock is being kept accurate by network time synchronization. An inaccurate clock breaks certificate and DNS security checks and makes log timestamps unreliable.",
			Category:    "system", Locus: LocusNode, Tier: TierDaily,
			Enabled: notDocker, Run: checkTimeSync,
		},
		{
			Name:        "ufw",
			Title:       "Firewall",
			Description: "Confirms the firewall is switched on and that every port the mail services need is allowed through it. Without the firewall the machine is exposed, and a blocked port makes that service unreachable.",
			Category:    "system", Locus: LocusNode, Tier: TierDaily,
			Enabled: notDocker, Run: checkUFW,
		},
		{
			Name:        "disk-health",
			Title:       "Disk health",
			Description: "Scans the system logs for disk read and write errors, which usually mean the drive is starting to fail. Healthy disks log nothing, so there is nothing to see until it fires.",
			Class:       ClassQuiet,
			Category:    "system", Locus: LocusNode, Tier: TierDaily,
			Enabled: notDocker, Run: checkDiskHealth,
		},
		{
			Name:        "system-mail-routing",
			Title:       "System mail routing",
			Description: "Confirms that mail the server sends to itself (bounce notices, status reports, cron output) has an up-to-date route to an administrator's mailbox. These routes are maintained automatically; a failure means the routing tables have stopped being rebuilt.",
			Class:       ClassQuiet,
			Category:    "system", Locus: LocusNode, Tier: TierFast,
			Enabled: func(d *Deps) bool { return d.MapsDir != "" },
			Run:     checkSystemMailRouting,
		},
		{
			Name:        "login-failures",
			Title:       "Failed login rate",
			Description: "Watches the rate of failed administrator login attempts and warns when it suddenly jumps far above the normal level. A sustained spike usually means someone is trying to guess passwords from many addresses at once, which per-IP blocking alone will not stop.",
			Category:    "system", Locus: LocusNode, Tier: TierHourly,
			Enabled: func(d *Deps) bool { return d.AuthFailures != nil },
			Run:     checkLoginFailures,
		},
	}
}

func checkLoginFailures(ctx context.Context, d *Deps, _ string, r *Reporter) {
	r.Step("Failed admin logins are near their usual rate", func(s *StepCtx) {
		// Heuristic 3 of 3: the daemon counts its own failed-login
		// lines (the ones fail2ban matches). This check samples the
		// cumulative count hourly; the per-hour increments over two
		// weeks form the baseline. fail2ban blocks individual IPs -
		// this surfaces the slow distributed attempts it cannot.
		count, err := d.AuthFailures(ctx)
		if err != nil {
			s.Skipf("auth-failure counter unavailable: %v", err)
			return
		}
		total := float64(count)
		samples, err := samplesSince(ctx, d, "auth-failures-total", d.Now().Add(-14*24*time.Hour))
		if err != nil {
			s.Skipf("no sample history: %v", err)
			return
		}
		recordSample(ctx, d, "auth-failures-total", total, 14*24*time.Hour)
		if len(samples) == 0 {
			s.Passf("Starting to track the failed-login rate; no baseline yet.")
			return
		}
		last := samples[len(samples)-1]
		latest := total - last.value
		if latest < 0 {
			s.Passf("No failed admin logins since the counter was last reset.")
			return // counter reset (fresh or restored database)
		}
		var deltas []float64
		for i := 1; i < len(samples); i++ {
			if delta := samples[i].value - samples[i-1].value; delta >= 0 {
				deltas = append(deltas, delta)
			}
		}
		if len(deltas) < 24 {
			s.Passf("Building a baseline for the usual failed-login rate.")
			return // under a day of baseline: nothing to deviate from
		}
		usual := median(deltas)
		s.Expect(fmt.Sprintf("around %.0f failed logins per hour", usual),
			fmt.Sprintf("%.0f in the last hour", latest))
		if latest > 10*usual && latest >= 30 {
			s.Warnf("There were %.0f failed admin login attempts in the last hour (usually around %.0f) - likely a distributed password-guessing attempt. fail2ban blocks repeat offenders per IP; consider watching the access log.",
				latest, usual)
			return
		}
		s.Passf("%.0f failed admin logins in the last hour, within the usual range (~%.0f).", latest, usual)
	})
}

func checkFreeDisk(ctx context.Context, d *Deps, _ string, r *Reporter) {
	haveFree := false
	var freeBytes float64
	r.Step("Disk has enough free space", func(s *StepCtx) {
		var st syscall.Statfs_t
		if err := syscall.Statfs(d.StorageRoot, &st); err != nil {
			s.Failf("cannot stat %s: %v", d.StorageRoot, err)
			return
		}
		total := st.Blocks * uint64(st.Frsize)
		free := st.Bavail * uint64(st.Frsize)
		haveFree, freeBytes = true, float64(free)
		msg := fmt.Sprintf("The disk has %.2f GB space remaining.", float64(free)/(1<<30))
		s.Expect("more than 30% free", fmt.Sprintf("%.1f%% free", 100*float64(free)/float64(total)))
		switch {
		case free <= total*15/100:
			s.Failf("%s", msg)
		case free <= total*30/100:
			s.Warnf("%s", msg)
		default:
			s.Passf("%.0f%%", 100*float64(total-free)/float64(total))
		}
	})
	r.Step("Disk is not trending toward full", func(s *StepCtx) {
		if !haveFree || d.Store == nil {
			s.Skipf("no disk reading")
			return
		}
		// Heuristic 1 of 3: fit two weeks of daily free-space samples
		// and warn when the line crosses zero within a week. Catches
		// runaway growth (log loops, mail floods) that the absolute
		// threshold only reports once the disk is already low.
		samples, err := samplesSince(ctx, d, "disk-free-bytes", d.Now().Add(-14*24*time.Hour))
		if err != nil {
			s.Skipf("no sample history: %v", err)
			return
		}
		recordDailySample(ctx, d, "disk-free-bytes", freeBytes, 30*24*time.Hour)
		samples = append(samples, sample{at: d.Now(), value: freeBytes})
		if full, ok := zeroCrossing(samples); ok && full.Before(d.Now().Add(7*24*time.Hour)) {
			s.Expect("free space steady or shrinking slowly",
				fmt.Sprintf("projected full around %s", full.UTC().Format("2006-01-02")))
			s.Warnf("At the current growth rate the disk will be full around %s. Find what is growing (mail, logs, backups) before it fills.",
				full.UTC().Format("2006-01-02"))
		}
	})
}

func checkFreeMemory(ctx context.Context, d *Deps, _ string, r *Reporter) {
	r.Step("System has enough free memory", func(s *StepCtx) {
		data, err := d.ReadFile("/proc/meminfo")
		if err != nil {
			s.Failf("cannot read /proc/meminfo: %v", err)
			return
		}
		total, okTotal := meminfoKB(string(data), "MemTotal")
		avail, okAvail := meminfoKB(string(data), "MemAvailable")
		if !okTotal || !okAvail || total == 0 {
			s.Failf("cannot parse /proc/meminfo")
			return
		}
		pctFree := 100 * avail / total
		msg := fmt.Sprintf("System memory is %d%% free.", pctFree)
		s.Expect("more than 20% free", fmt.Sprintf("%d%% free", pctFree))
		switch {
		case pctFree < 10:
			s.Failf("%s", msg)
		case pctFree < 20:
			s.Warnf("%s", msg)
		default:
			s.Passf("%d%%", 100-pctFree)
		}
	})
}

// meminfoKB reads one /proc/meminfo field; ok is false when the field
// is absent or unparseable (an ancient kernel without MemAvailable),
// so a missing reading is never mistaken for zero free memory.
func meminfoKB(meminfo, field string) (int64, bool) {
	for _, line := range strings.Split(meminfo, "\n") {
		if rest, ok := strings.CutPrefix(line, field+":"); ok {
			v, err := strconv.ParseInt(strings.TrimSuffix(strings.TrimSpace(rest), " kB"), 10, 64)
			return v, err == nil
		}
	}
	return 0, false
}

func checkSoftwareUpdates(ctx context.Context, d *Deps, _ string, r *Reporter) {
	r.Step("No reboot is pending", func(s *StepCtx) {
		if _, err := d.ReadFile("/var/run/reboot-required"); err == nil {
			s.Failf("System updates have been installed and a reboot of the machine is required.")
			s.Hint("system.reboot")
			return
		}
		s.Passf("No reboot is pending.")
	})
	r.Step("System software is up to date", func(s *StepCtx) {
		// Simulation only: reads the package lists unattended-upgrades
		// already fetched, needs no root and takes no lock.
		out, err := d.Run(ctx, "apt-get", "-s", "-o", "Debug::NoLocking=true", "-q", "upgrade")
		if err != nil {
			s.Warnf("could not list software updates: %v", err)
			return
		}
		var pkgs []string
		for _, line := range strings.Split(out, "\n") {
			if f := strings.Fields(line); len(f) >= 3 && f[0] == "Inst" {
				pkgs = append(pkgs, f[1])
			}
		}
		if len(pkgs) > 0 {
			s.Failf("There are %d software packages that can be updated.", len(pkgs))
			s.Expect("up to date", strings.Join(pkgs, ", "))
			return
		}
		s.Passf("All software packages are up to date.")
	})
}

func checkSSHPasswordAuth(ctx context.Context, d *Deps, _ string, r *Reporter) {
	r.Step("SSH disallows password-based login", func(s *StepCtx) {
		value, ok := sshdDirective(d, "passwordauthentication")
		if !ok {
			// OpenSSH's compiled-in default is yes; Ubuntu images
			// normally set no in sshd_config.d. Absent = permissive.
			value = "yes"
		}
		s.Expect("PasswordAuthentication no", "PasswordAuthentication "+value)
		if value != "no" {
			s.Failf("The SSH server on this machine permits password-based login. Add your SSH public key to $HOME/.ssh/authorized_keys, check that you can log in without a password, set 'PasswordAuthentication no' in /etc/ssh/sshd_config, and restart ssh.")
			return
		}
		s.Passf("SSH accepts only key-based logins.")
	})
}

// sshdDirective finds the first value of a directive across
// sshd_config and its Include files, mirroring sshd's first-match
// semantics. Keyword matching is case-insensitive.
func sshdDirective(d *Deps, keyword string) (string, bool) {
	return sshdScan(d, "/etc/ssh/sshd_config", keyword, 0)
}

func sshdScan(d *Deps, path, keyword string, depth int) (string, bool) {
	if depth > 3 || d.ReadFile == nil {
		return "", false
	}
	data, err := d.ReadFile(path)
	if err != nil {
		return "", false
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(strings.TrimSpace(line))
		if len(f) < 2 || strings.HasPrefix(f[0], "#") {
			continue
		}
		key := strings.ToLower(f[0])
		if key == "include" {
			pattern := f[1]
			if !filepath.IsAbs(pattern) {
				pattern = "/etc/ssh/" + pattern
			}
			matches, _ := filepath.Glob(pattern)
			for _, m := range matches {
				if v, ok := sshdScan(d, m, keyword, depth+1); ok {
					return v, true
				}
			}
			continue
		}
		if key == "match" {
			// Directives below a Match block are conditional; the
			// global value must appear before it.
			return "", false
		}
		if key == keyword {
			return strings.ToLower(f[1]), true
		}
	}
	return "", false
}

func checkTimeSync(ctx context.Context, d *Deps, _ string, r *Reporter) {
	r.Step("System time is synchronized", func(s *StepCtx) {
		out, err := d.Run(ctx, "timedatectl", "status")
		if err != nil {
			s.Warnf("Could not check time synchronization status (timedatectl not available).")
			return
		}
		lower := strings.ToLower(out)
		if !strings.Contains(lower, "ntp service: active") &&
			!strings.Contains(lower, "system clock synchronized: yes") &&
			!strings.Contains(lower, "ntp synchronized: yes") {
			s.Failf("System clock is not synchronized. Time synchronization is critical for DNSSEC, SSL certificates, and log accuracy. Enable NTP with: timedatectl set-ntp true")
			return
		}
		s.Passf("The system clock is synchronized via NTP.")
	})
}

func checkUFW(ctx context.Context, d *Deps, _ string, r *Reporter) {
	var rules []string
	r.Step("Firewall is active", func(s *StepCtx) {
		if !d.RootContext {
			s.Skipf("firewall state is only readable by root - run boxctl doctor to verify")
			return
		}
		out, err := d.Run(ctx, "ufw", "status")
		if err != nil {
			s.Warnf("The firewall is not working on this machine. To investigate run 'sudo ufw status'.")
			return
		}
		lines := strings.Split(out, "\n")
		if len(lines) == 0 || strings.TrimSpace(lines[0]) != "Status: active" {
			s.Failf("The firewall is disabled on this machine, leaving every service exposed. Unless an external firewall protects the system, connect via ssh and run: ufw enable.")
			return
		}
		rules = lines[1:]
		s.Passf("The firewall (ufw) is active.")
	})
	r.Step("Required public ports are allowed through the firewall", func(s *StepCtx) {
		if rules == nil {
			s.Skipf("firewall rules not readable")
			return
		}
		var missing, checked []string
		for _, p := range probeTable(d) {
			if !p.Public || (p.Enabled != nil && !p.Enabled(d)) {
				continue
			}
			checked = append(checked, strconv.Itoa(p.Port))
			allowed := false
			for _, line := range rules {
				if f := strings.Fields(line); len(f) > 0 &&
					(f[0] == strconv.Itoa(p.Port) || strings.HasPrefix(f[0], strconv.Itoa(p.Port)+"/")) {
					allowed = true
					break
				}
			}
			if !allowed {
				missing = append(missing, fmt.Sprintf("Port %d (%s) should be allowed in the firewall, please re-run the setup.", p.Port, p.Label))
			}
		}
		if len(missing) > 0 {
			s.Failf("%s", strings.Join(missing, "; "))
			return
		}
		s.Passf("All required public ports (%s) are allowed through the firewall.", strings.Join(checked, ", "))
	})
}

func checkDiskHealth(ctx context.Context, d *Deps, _ string, r *Reporter) {
	r.Step("No disk I/O errors in system logs", func(s *StepCtx) {
		// journalctl -k needs membership in adm/systemd-journal; try
		// it and be honest when this context cannot read the journal.
		out, err := d.Run(ctx, "journalctl", "-k", "-q", "--no-pager", "--since", "-24 hours")
		if err != nil {
			if d.RootContext {
				s.Warnf("could not read the kernel log: %v", err)
			} else {
				s.Skipf("kernel log not readable from this context - run boxctl doctor to verify")
			}
			return
		}
		patterns := []string{"i/o error", "buffer i/o error", "disk error", "read error",
			"write error", "medium error", "disk failure"}
		var found []string
		for _, line := range strings.Split(out, "\n") {
			lower := strings.ToLower(line)
			for _, p := range patterns {
				if strings.Contains(lower, p) {
					found = append(found, strings.TrimSpace(line))
					break
				}
			}
		}
		if len(found) > 0 {
			sample := found
			if len(sample) > 3 {
				sample = sample[len(sample)-3:]
			}
			for i, l := range sample {
				if len(l) > 200 {
					sample[i] = l[:200]
				}
			}
			s.Failf("Disk I/O errors detected in system logs (%d in the last 24h). This may indicate failing hardware. Recent: %s", len(found), strings.Join(sample, "; "))
			return
		}
		s.Passf("No disk I/O errors in the last 24 hours.")
	})
}

// checkSystemMailRouting probes the materialized alias map end to end:
// store -> renderer -> postmap -> file on disk. It replaced the old
// system-alias check that demanded a manually created alias; routing
// is derived now (materialize/system.go), so a healthy box passes
// from its first run with nothing for the operator to do.
func checkSystemMailRouting(ctx context.Context, d *Deps, _ string, r *Reporter) {
	mapPath := filepath.Join(d.MapsDir, "virtual-alias-maps")
	var content []byte
	r.Step("The mail routing tables have been rendered", func(s *StepCtx) {
		var err error
		content, err = d.ReadFile(mapPath)
		if err != nil {
			s.Hint("Check the materializer: journalctl -u naust-managerd | grep materialize")
			s.Failf("The routing tables Postfix reads are missing (%s). Mail is being handled with stale or empty routes.", mapPath)
			return
		}
		s.Passf("The mail routing tables are current.")
	})
	r.Step("Mail for this server's operator reaches an administrator", func(s *StepCtx) {
		if content == nil {
			s.Skipf("routing tables missing")
			return
		}
		addr := "root@" + d.PrimaryHostname
		for _, line := range strings.Split(string(content), "\n") {
			if strings.HasPrefix(line, addr+" ") {
				s.Passf("Mail to %s routes to an administrator's mailbox.", addr)
				return
			}
		}
		s.Expect(addr+" -> an administrator's mailbox", "no route")
		s.Hint("This route is added automatically when an administrator account exists. If one does, the materializer is failing - check journalctl -u naust-managerd.")
		s.Failf("Mail to %s has nowhere to go: bounce notices and system reports would be lost.", addr)
	})
}
