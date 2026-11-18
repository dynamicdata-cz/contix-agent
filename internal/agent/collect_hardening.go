package agent

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

/* ---------------- hardening facts ----------------
 * The agent only reports facts (current values); CONTIX evaluates them against its check catalogue
 * (CIS Benchmark / NÚKIB recommendations), so thresholds can change without a new agent.
 * Facts never contain file contents, password hashes or secrets – only settings, modes and names.
 */

// Fact is one hardening fact value.
type Fact struct {
	V string `json:"v"`
}

// hardeningSysctls are kernel parameters read from /proc/sys.
var hardeningSysctls = []string{
	"net.ipv4.ip_forward",
	"net.ipv4.conf.all.accept_redirects", "net.ipv4.conf.default.accept_redirects",
	"net.ipv4.conf.all.secure_redirects", "net.ipv4.conf.default.secure_redirects",
	"net.ipv4.conf.all.send_redirects", "net.ipv4.conf.default.send_redirects",
	"net.ipv4.conf.all.accept_source_route", "net.ipv4.conf.default.accept_source_route",
	"net.ipv4.conf.all.rp_filter", "net.ipv4.conf.default.rp_filter",
	"net.ipv4.conf.all.log_martians", "net.ipv4.conf.default.log_martians",
	"net.ipv4.tcp_syncookies", "net.ipv4.icmp_echo_ignore_broadcasts", "net.ipv4.icmp_ignore_bogus_error_responses",
	"net.ipv6.conf.all.accept_redirects", "net.ipv6.conf.default.accept_redirects",
	"net.ipv6.conf.all.accept_source_route", "net.ipv6.conf.all.accept_ra", "net.ipv6.conf.all.forwarding",
	"kernel.randomize_va_space", "kernel.kptr_restrict", "kernel.dmesg_restrict", "kernel.yama.ptrace_scope",
	"kernel.unprivileged_bpf_disabled", "kernel.sysrq", "kernel.core_uses_pid",
	"fs.protected_hardlinks", "fs.protected_symlinks", "fs.protected_fifos", "fs.protected_regular", "fs.suid_dumpable",
	"user.max_user_namespaces",
}

// hardeningMounts are mount points whose options are checked.
var hardeningMounts = []string{"/tmp", "/var/tmp", "/dev/shm", "/home", "/var", "/var/log", "/var/log/audit"}

// hardeningFiles are files whose mode and owner are checked.
var hardeningFiles = []string{
	"/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow", "/etc/passwd-", "/etc/shadow-",
	"/etc/ssh/sshd_config", "/etc/crontab", "/etc/cron.d", "/etc/cron.daily", "/etc/sudoers",
	"/boot/grub/grub.cfg", "/boot/grub2/grub.cfg", "/etc/at.allow", "/etc/cron.allow",
}

// hardeningModules are kernel modules that should not be loadable on servers (CIS).
var hardeningModules = []string{"usb_storage", "cramfs", "freevxfs", "hfs", "hfsplus", "jffs2", "udf", "dccp", "sctp", "rds", "tipc", "firewire_core", "bluetooth"}

func (c *Collector) exists(p string) bool {
	_, err := os.Stat(c.path(p))
	return err == nil
}

// mountOptions parses mountinfo (of PID 1 – the agent itself runs with a private /tmp).
func (c *Collector) mountOptions() map[string]string {
	b, err := c.read("/proc/1/mountinfo")
	if err != nil {
		b, err = c.read("/proc/self/mountinfo")
		if err != nil {
			return nil
		}
	}
	m := map[string]string{}
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Fields(l)
		if len(f) < 10 {
			continue
		}
		mp := f[4]
		opts := strings.Split(f[5], ",")
		// super options after the "-" separator (fs type, source, super options)
		for i, x := range f {
			if x == "-" && i+3 < len(f) {
				for _, o := range strings.Split(f[i+3], ",") {
					if o == "noexec" || o == "nosuid" || o == "nodev" {
						opts = append(opts, o)
					}
				}
				break
			}
		}
		keep := []string{}
		seen := map[string]bool{}
		for _, o := range opts {
			if (o == "ro" || o == "rw" || o == "noexec" || o == "nosuid" || o == "nodev") && !seen[o] {
				keep = append(keep, o)
				seen[o] = true
			}
		}
		sort.Strings(keep)
		m[mp] = strings.Join(keep, ",") // last mount on a path wins (over-mounts)
	}
	return m
}

// keyValues reads "KEY value" or "key = value" settings from a config file (comments skipped).
func keyValues(b []byte, sep string) map[string]string {
	m := map[string]string{}
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		var k, v string
		if sep == "" {
			f := strings.Fields(l)
			if len(f) < 2 {
				continue
			}
			k, v = f[0], f[1]
		} else {
			var ok bool
			k, v, ok = strings.Cut(l, sep)
			if !ok {
				continue
			}
		}
		m[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return m
}

// configFiles returns a file and the files of its drop-in directory.
func (c *Collector) configFiles(file, dir string) [][]byte {
	var out [][]byte
	if b, err := c.read(file); err == nil {
		out = append(out, b)
	}
	if dir != "" {
		ents, _ := os.ReadDir(c.path(dir))
		for _, e := range ents {
			if !e.IsDir() {
				if b, err := c.read(filepath.Join(dir, e.Name())); err == nil {
					out = append(out, b)
				}
			}
		}
	}
	return out
}

func (c *Collector) hardening(ctx context.Context, s *Snapshot) error {
	put := func(k, v string) { s.put(ModHardening, k, Fact{V: trunc(v, 500)}) }

	for _, k := range hardeningSysctls {
		if b, err := c.read("/proc/sys/" + strings.ReplaceAll(k, ".", "/")); err == nil {
			put("sysctl."+k, strings.Join(strings.Fields(string(b)), " "))
		}
	}

	if mo := c.mountOptions(); mo != nil {
		for _, p := range hardeningMounts {
			if v, ok := mo[p]; ok {
				put("mount."+p, v)
			} else {
				put("mount."+p, "-") // not a separate mount
			}
		}
	}

	for _, p := range hardeningFiles {
		fi, err := os.Stat(c.path(p))
		if err != nil {
			continue
		}
		put("perm."+p, fmt.Sprintf("%04o %d:%d", fi.Mode().Perm(), fileUID(fi), fileGID(fi)))
	}

	// mandatory access control
	if b, err := c.read("/sys/module/apparmor/parameters/enabled"); err == nil {
		v := "disabled"
		if strings.TrimSpace(string(b)) == "Y" {
			v = "enabled"
			if pb, err := c.read("/sys/kernel/security/apparmor/profiles"); err == nil {
				enf, cmp := 0, 0
				for _, l := range strings.Split(string(pb), "\n") {
					switch {
					case strings.HasSuffix(l, "(enforce)"):
						enf++
					case strings.HasSuffix(l, "(complain)"):
						cmp++
					}
				}
				v = fmt.Sprintf("enabled enforce=%d complain=%d", enf, cmp)
			}
		}
		put("mac.apparmor", v)
	} else {
		put("mac.apparmor", "absent")
	}
	if b, err := c.read("/sys/fs/selinux/enforce"); err == nil {
		if strings.TrimSpace(string(b)) == "1" {
			put("mac.selinux", "enforcing")
		} else {
			put("mac.selinux", "permissive")
		}
	} else {
		put("mac.selinux", "absent")
	}

	// time synchronisation
	if out, err := c.run(ctx, "timedatectl", "show", "-p", "NTPSynchronized", "--value"); err == nil {
		put("time.synced", strings.TrimSpace(string(out)))
	}

	// password policy
	if b, err := c.read("/etc/login.defs"); err == nil {
		kv := keyValues(b, "")
		for _, k := range []string{"PASS_MAX_DAYS", "PASS_MIN_DAYS", "PASS_WARN_AGE", "UMASK", "ENCRYPT_METHOD"} {
			if v, ok := kv[k]; ok {
				put("logindefs."+k, v)
			}
		}
	}
	pq := map[string]string{}
	for _, b := range c.configFiles("/etc/security/pwquality.conf", "/etc/security/pwquality.conf.d") {
		for k, v := range keyValues(b, "=") {
			pq[k] = v
		}
	}
	for _, k := range []string{"minlen", "minclass", "dcredit", "ucredit", "lcredit", "ocredit"} {
		if v, ok := pq[k]; ok {
			put("pwquality."+k, v)
		}
	}
	var pam []byte
	for _, f := range []string{"/etc/pam.d/common-auth", "/etc/pam.d/common-password", "/etc/pam.d/system-auth", "/etc/pam.d/password-auth"} {
		if b, err := c.read(f); err == nil {
			pam = append(pam, b...)
		}
	}
	if pam != nil {
		lock := "none"
		active := regexp.MustCompile(`(?m)^\s*[a-z]+\s+\S+\s+pam_(faillock|tally2)\.so`)
		if m := active.FindSubmatch(pam); m != nil {
			lock = string(m[1])
		}
		put("pam.lockout", lock)
		put("pam.pwquality", strconv.FormatBool(regexp.MustCompile(`(?m)^\s*password\s+\S+\s+pam_(pwquality|cracklib)\.so`).Match(pam)))
	}

	// accounts with an empty password field (names only)
	if b, err := c.read("/etc/shadow"); err == nil {
		var empty []string
		for _, l := range strings.Split(string(b), "\n") {
			f := strings.Split(l, ":")
			if len(f) >= 2 && f[0] != "" && f[1] == "" {
				empty = append(empty, trunc(f[0], 64))
			}
		}
		put("accounts.emptyPassword", strings.Join(empty, ","))
	}

	// sudo rules without a password (subject only: user or %group)
	nopw := map[string]bool{}
	for _, b := range c.configFiles("/etc/sudoers", "/etc/sudoers.d") {
		for _, l := range strings.Split(string(b), "\n") {
			l = strings.TrimSpace(l)
			if l == "" || strings.HasPrefix(l, "#") || strings.HasPrefix(l, "Defaults") {
				continue
			}
			if strings.Contains(l, "NOPASSWD") || strings.Contains(l, "!authenticate") {
				if f := strings.Fields(l); len(f) > 0 && len(nopw) < 50 {
					nopw[trunc(f[0], 64)] = true
				}
			}
		}
	}
	put("sudo.nopasswd", strings.Join(sortedKeys(nopw), ","))

	// core dumps
	core := "-"
	for _, b := range c.configFiles("/etc/systemd/coredump.conf", "/etc/systemd/coredump.conf.d") {
		if v, ok := keyValues(b, "=")["Storage"]; ok {
			core = v
		}
	}
	put("core.storage", core)
	limit := "-"
	for _, b := range c.configFiles("/etc/security/limits.conf", "/etc/security/limits.d") {
		for _, l := range strings.Split(string(b), "\n") {
			f := strings.Fields(l)
			if len(f) == 4 && f[0] == "*" && f[1] == "hard" && f[2] == "core" {
				limit = f[3]
			}
		}
	}
	put("core.hardLimit", limit)

	// kernel modules: loaded / blocked (install /bin/false or blacklist) / allowed
	loaded := map[string]bool{}
	if b, err := c.read("/proc/modules"); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if f := strings.Fields(l); len(f) > 0 {
				loaded[f[0]] = true
			}
		}
	}
	var modprobe []byte
	for _, b := range c.configFiles("", "/etc/modprobe.d") {
		modprobe = append(modprobe, b...)
	}
	for _, m := range hardeningModules {
		v := "allowed"
		alt := strings.ReplaceAll(m, "_", "-")
		re := regexp.MustCompile(`(?m)^\s*(install\s+(` + m + `|` + alt + `)\s+/(usr/)?bin/(false|true)|blacklist\s+(` + m + `|` + alt + `))\b`)
		if re.Match(modprobe) {
			v = "blocked"
		}
		if loaded[m] {
			v = "loaded"
		}
		put("module."+m, v)
	}

	// boot loader password (only whether it is set)
	for _, p := range []string{"/boot/grub/grub.cfg", "/boot/grub2/grub.cfg", "/boot/grub2/user.cfg"} {
		if b, err := c.read(p); err == nil {
			put("boot.password", strconv.FormatBool(strings.Contains(string(b), "password_pbkdf2") || strings.Contains(string(b), "GRUB2_PASSWORD")))
			break
		}
	}

	// logging and audit
	jp := "auto"
	for _, b := range c.configFiles("/etc/systemd/journald.conf", "/etc/systemd/journald.conf.d") {
		if v, ok := keyValues(b, "=")["Storage"]; ok {
			jp = v
		}
	}
	if jp == "auto" && c.exists("/var/log/journal") {
		jp = "persistent"
	}
	put("journald.storage", jp)
	remote := false
	for _, b := range c.configFiles("/etc/rsyslog.conf", "/etc/rsyslog.d") {
		if regexp.MustCompile(`(?m)^\s*([^#\s]\S*\s+@@?\S+|.*type\s*=\s*"omfwd")`).Match(b) {
			remote = true
		}
	}
	put("syslog.remote", strconv.FormatBool(remote))
	rules := 0
	for _, b := range c.configFiles("/etc/audit/audit.rules", "/etc/audit/rules.d") {
		for _, l := range strings.Split(string(b), "\n") {
			if l = strings.TrimSpace(l); strings.HasPrefix(l, "-a") || strings.HasPrefix(l, "-w") {
				rules++
			}
		}
	}
	if c.exists("/etc/audit") {
		put("audit.rules", strconv.Itoa(rules))
	}

	// login banner exposes the OS version?
	if b, err := c.read("/etc/issue.net"); err == nil {
		put("banner.osInfo", strconv.FormatBool(regexp.MustCompile(`\\[mrsv]|Ubuntu|Debian|Red Hat|CentOS|Rocky|Alma`).Match(b)))
	}
	return nil
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
