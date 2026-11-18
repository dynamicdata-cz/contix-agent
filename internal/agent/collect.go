package agent

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Collector reads host state. It only reads files under Root and runs a fixed set of
// read-only programs (never a shell, never anything received from the network).
// Secrets never leave the host: no password hashes, no key material (fingerprints only),
// no cron command lines (program + hash only).
type Collector struct {
	// Root is prepended to all file paths (tests); empty = "/".
	Root string
	// Exec runs a read-only program; nil = programs are not available (tests, unsupported OS).
	Exec func(ctx context.Context, name string, args ...string) ([]byte, error)
	// EngineGet replaces the container engine API (tests); nil = the local engine socket.
	EngineGet func(ctx context.Context, path string) ([]byte, error)
	// Now replaces the clock (tests); nil = time.Now.
	Now func() time.Time

	sysCache *SystemState
	sysAt    time.Time
}

func (c *Collector) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// NewCollector returns a collector for the running host.
func NewCollector() *Collector { return &Collector{Exec: runProgram} }

// runProgram executes a program with a fixed argument list, C locale and a time limit.
func runProgram(ctx context.Context, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	path, err := exec.LookPath(name)
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = []string{"LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "SYSTEMD_COLORS=0", "SYSTEMD_PAGER="}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

func (c *Collector) path(p string) string {
	if c.Root == "" {
		return p
	}
	return filepath.Join(c.Root, p)
}

func (c *Collector) read(p string) ([]byte, error) { return os.ReadFile(c.path(p)) }

func (c *Collector) run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if c.Exec == nil {
		return nil, errors.New("program execution not available")
	}
	return c.Exec(ctx, name, args...)
}

// Collect gathers the host info and the requested modules.
func (c *Collector) Collect(ctx context.Context, modules []string) *Snapshot {
	s := &Snapshot{Host: c.host(), Modules: map[string]map[string]json.RawMessage{}, Errors: map[string]string{}}
	for _, m := range modules {
		var err error
		switch m {
		case ModPorts:
			err = c.ports(s)
		case ModServices:
			err = c.services(ctx, s)
		case ModPackages:
			err = c.packages(ctx, s)
		case ModAccounts:
			err = c.accounts(s)
		case ModSSHKeys:
			err = c.sshKeys(s)
		case ModFirewall:
			err = c.firewall(ctx, s)
		case ModScheduled:
			err = c.scheduled(ctx, s)
		case ModContainers:
			err = c.containers(ctx, s)
		case ModImages:
			err = c.images(ctx, s)
		case ModEngine:
			err = c.engine(ctx, s)
		case ModSystem:
			err = c.system(ctx, s)
		case ModSSHD:
			err = c.sshd(ctx, s)
		case ModHardening:
			err = c.hardening(ctx, s)
		default:
			err = fmt.Errorf("unknown module")
		}
		if err != nil {
			s.Errors[m] = err.Error()
			delete(s.Modules, m)
		} else if s.Modules[m] == nil {
			s.Modules[m] = map[string]json.RawMessage{}
		}
	}
	if len(s.Errors) == 0 {
		s.Errors = nil
	}
	return s
}

/* ---------------- host ---------------- */

func firstLine(b []byte) string {
	line, _, _ := strings.Cut(strings.TrimSpace(string(b)), "\n")
	return strings.TrimSpace(line)
}

func (c *Collector) host() HostInfo {
	h := HostInfo{}
	if b, err := c.read("/proc/sys/kernel/hostname"); err == nil {
		h.Hostname = firstLine(b)
	}
	if h.Hostname == "" && c.Root == "" {
		h.Hostname, _ = os.Hostname()
	}
	if b, err := c.read("/etc/machine-id"); err == nil {
		h.HostID = firstLine(b)
	}
	if h.HostID == "" {
		if b, err := c.read("/sys/class/dmi/id/product_uuid"); err == nil {
			h.HostID = strings.ToLower(firstLine(b))
		}
	}
	if b, err := c.read("/etc/os-release"); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if v, ok := strings.CutPrefix(l, "PRETTY_NAME="); ok {
				h.OS = strings.Trim(v, `"'`)
			}
		}
	}
	if b, err := c.read("/proc/sys/kernel/osrelease"); err == nil {
		h.Kernel = firstLine(b)
	}
	if b, err := c.read("/proc/uptime"); err == nil {
		if f, err := strconv.ParseFloat(strings.Fields(string(b) + " 0")[0], 64); err == nil {
			h.Uptime = int64(f)
		}
	}
	if c.Root == "" {
		addrs, _ := net.InterfaceAddrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && !ipn.IP.IsLoopback() && !ipn.IP.IsLinkLocalUnicast() {
				h.IPs = append(h.IPs, ipn.IP.String())
			}
		}
	}
	return h
}

/* ---------------- ports ---------------- */

// Port is a listening socket.
type Port struct {
	Proto   string `json:"proto"`
	Address string `json:"address"`
	Port    int    `json:"port"`
	Process string `json:"process,omitempty"`
}

// parseProcAddr decodes "0100007F:0016" (IPv4) or a 32-hex-digit IPv6 address from /proc/net.
func parseProcAddr(s string) (net.IP, int, error) {
	hexIP, hexPort, ok := strings.Cut(s, ":")
	if !ok {
		return nil, 0, errors.New("bad address")
	}
	port, err := strconv.ParseUint(hexPort, 16, 16)
	if err != nil {
		return nil, 0, err
	}
	raw, err := hex.DecodeString(hexIP)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return nil, 0, errors.New("bad address")
	}
	ip := make(net.IP, len(raw))
	for i := 0; i < len(raw); i += 4 { // each 32-bit word is in host (little-endian) order
		ip[i], ip[i+1], ip[i+2], ip[i+3] = raw[i+3], raw[i+2], raw[i+1], raw[i]
	}
	return ip, int(port), nil
}

// socketOwners maps socket inode -> process name by scanning /proc/<pid>/fd.
func (c *Collector) socketOwners() map[string]string {
	out := map[string]string{}
	procs, _ := os.ReadDir(c.path("/proc"))
	for _, p := range procs {
		if _, err := strconv.Atoi(p.Name()); err != nil {
			continue
		}
		comm, _ := c.read("/proc/" + p.Name() + "/comm")
		name := firstLine(comm)
		fds, err := os.ReadDir(c.path("/proc/" + p.Name() + "/fd"))
		if err != nil {
			continue
		}
		for _, fd := range fds {
			link, err := os.Readlink(c.path("/proc/" + p.Name() + "/fd/" + fd.Name()))
			if err == nil && strings.HasPrefix(link, "socket:[") {
				out[strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")] = name
			}
		}
	}
	return out
}

func (c *Collector) ports(s *Snapshot) error {
	owners := c.socketOwners()
	found := false
	for _, f := range []struct{ file, proto, state string }{
		{"/proc/net/tcp", "tcp", "0A"}, {"/proc/net/tcp6", "tcp", "0A"},
		{"/proc/net/udp", "udp", "07"}, {"/proc/net/udp6", "udp", "07"},
	} {
		b, err := c.read(f.file)
		if err != nil {
			continue
		}
		found = true
		for i, line := range strings.Split(string(b), "\n") {
			fl := strings.Fields(line)
			if i == 0 || len(fl) < 10 || fl[3] != f.state {
				continue
			}
			if f.proto == "udp" {
				if _, rport, err := parseProcAddr(fl[2]); err != nil || rport != 0 {
					continue // connected UDP socket, not a listener
				}
			}
			ip, port, err := parseProcAddr(fl[1])
			if err != nil {
				continue
			}
			p := Port{Proto: f.proto, Address: ip.String(), Port: port, Process: owners[fl[9]]}
			s.put(ModPorts, fmt.Sprintf("%s/%s", p.Proto, net.JoinHostPort(p.Address, strconv.Itoa(p.Port))), p)
		}
	}
	if !found {
		return errors.New("/proc/net not readable")
	}
	return nil
}

/* ---------------- services (systemd) ---------------- */

// Service is a systemd service unit.
type Service struct {
	Name    string `json:"name"`
	Active  string `json:"active"`
	Sub     string `json:"sub"`
	Enabled string `json:"enabled,omitempty"`
}

func (c *Collector) services(ctx context.Context, s *Snapshot) error {
	units, err := c.run(ctx, "systemctl", "list-units", "--type=service", "--all", "--no-legend", "--plain", "--no-pager")
	if err != nil {
		return err
	}
	files, _ := c.run(ctx, "systemctl", "list-unit-files", "--type=service", "--no-legend", "--no-pager")
	enabled := map[string]string{}
	for _, l := range strings.Split(string(files), "\n") {
		if f := strings.Fields(l); len(f) >= 2 {
			enabled[f[0]] = f[1]
		}
	}
	seen := map[string]bool{}
	for _, l := range strings.Split(string(units), "\n") {
		f := strings.Fields(strings.TrimLeft(l, "●* "))
		if len(f) < 4 || !strings.HasSuffix(f[0], ".service") || f[1] == "not-found" {
			continue
		}
		seen[f[0]] = true
		s.put(ModServices, f[0], Service{Name: f[0], Active: f[2], Sub: f[3], Enabled: enabled[f[0]]})
	}
	// enabled but never loaded units (e.g. disabled after boot) are still relevant
	for name, st := range enabled {
		if !seen[name] && !strings.Contains(name, "@.") && (st == "enabled" || st == "enabled-runtime") {
			s.put(ModServices, name, Service{Name: name, Active: "inactive", Sub: "dead", Enabled: st})
		}
	}
	return nil
}

/* ---------------- packages ---------------- */

// Package is an installed package.
type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Arch    string `json:"arch,omitempty"`
}

func (c *Collector) packages(ctx context.Context, s *Snapshot) error {
	if b, err := c.read("/var/lib/dpkg/status"); err == nil {
		var p Package
		installed := false
		flush := func() {
			if p.Name != "" && installed {
				s.put(ModPackages, p.Name+":"+p.Arch, p)
			}
			p, installed = Package{}, false
		}
		for _, l := range strings.Split(string(b), "\n") {
			switch {
			case l == "":
				flush()
			case strings.HasPrefix(l, "Package: "):
				p.Name = strings.TrimPrefix(l, "Package: ")
			case strings.HasPrefix(l, "Version: "):
				p.Version = strings.TrimPrefix(l, "Version: ")
			case strings.HasPrefix(l, "Architecture: "):
				p.Arch = strings.TrimPrefix(l, "Architecture: ")
			case strings.HasPrefix(l, "Status: "):
				installed = strings.HasSuffix(l, " installed") && !strings.Contains(l, "not-installed")
			}
		}
		flush()
		return nil
	}
	out, err := c.run(ctx, "rpm", "-qa", "--qf", `%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n`)
	if err != nil {
		return errors.New("no dpkg status and rpm not available")
	}
	for _, l := range strings.Split(string(out), "\n") {
		if f := strings.Split(l, "\t"); len(f) == 3 && f[0] != "" && f[0] != "gpg-pubkey" {
			s.put(ModPackages, f[0]+":"+f[2], Package{Name: f[0], Version: f[1], Arch: f[2]})
		}
	}
	return nil
}

/* ---------------- accounts ---------------- */

// Account is a local user account (no password hash is ever read out).
type Account struct {
	Name       string `json:"name"`
	UID        int    `json:"uid"`
	GID        int    `json:"gid"`
	Home       string `json:"home"`
	Shell      string `json:"shell"`
	Login      bool   `json:"login"`
	Admin      bool   `json:"admin"`
	Locked     *bool  `json:"locked,omitempty"`
	NoPassword bool   `json:"noPassword,omitempty"`
}

type passwdEntry struct {
	name, home, shell string
	uid, gid          int
}

func (c *Collector) passwd() ([]passwdEntry, error) {
	b, err := c.read("/etc/passwd")
	if err != nil {
		return nil, err
	}
	var out []passwdEntry
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Split(l, ":")
		if len(f) < 7 || strings.HasPrefix(l, "#") {
			continue
		}
		uid, err1 := strconv.Atoi(f[2])
		gid, err2 := strconv.Atoi(f[3])
		if err1 != nil || err2 != nil {
			continue
		}
		out = append(out, passwdEntry{name: f[0], uid: uid, gid: gid, home: f[5], shell: f[6]})
	}
	return out, nil
}

var adminGroups = map[string]bool{"sudo": true, "wheel": true, "admin": true}

func (c *Collector) accounts(s *Snapshot) error {
	users, err := c.passwd()
	if err != nil {
		return err
	}
	admins := map[string]bool{}
	adminGIDs := map[int]bool{}
	if b, err := c.read("/etc/group"); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			f := strings.Split(l, ":")
			if len(f) < 4 || !adminGroups[f[0]] {
				continue
			}
			if gid, err := strconv.Atoi(f[2]); err == nil {
				adminGIDs[gid] = true
			}
			for _, m := range strings.Split(f[3], ",") {
				if m = strings.TrimSpace(m); m != "" {
					admins[m] = true
				}
			}
		}
	}
	type shadow struct{ locked, empty bool }
	shadows := map[string]shadow{}
	if b, err := c.read("/etc/shadow"); err == nil { // only the state of the field, never its content
		for _, l := range strings.Split(string(b), "\n") {
			f := strings.Split(l, ":")
			if len(f) >= 2 {
				shadows[f[0]] = shadow{locked: strings.HasPrefix(f[1], "!") || strings.HasPrefix(f[1], "*"), empty: f[1] == ""}
			}
		}
	}
	for _, u := range users {
		a := Account{Name: u.name, UID: u.uid, GID: u.gid, Home: u.home, Shell: u.shell, Admin: admins[u.name] || adminGIDs[u.gid] || u.uid == 0}
		base := filepath.Base(u.shell)
		a.Login = u.shell != "" && base != "nologin" && base != "false" && base != "sync" && base != "shutdown" && base != "halt"
		if sh, ok := shadows[u.name]; ok {
			locked := sh.locked
			a.Locked = &locked
			a.NoPassword = sh.empty
		}
		s.put(ModAccounts, u.name, a)
	}
	return nil
}

/* ---------------- SSH authorized keys ---------------- */

// SSHKey is an authorized key: fingerprint, type and length only – never the key itself.
type SSHKey struct {
	User        string   `json:"user"`
	File        string   `json:"file"`
	Type        string   `json:"type"`
	Bits        int      `json:"bits,omitempty"`
	Fingerprint string   `json:"fingerprint"`
	Comment     string   `json:"comment,omitempty"`
	Options     []string `json:"options,omitempty"`
}

var keyTypeRe = regexp.MustCompile(`^(ssh-(rsa|dss|ed25519)|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com)$`)

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// splitOptions splits a leading options field (comma separated, quotes may contain spaces/commas).
func splitOptions(line string) (opts []string, rest string) {
	inQ := false
	start := 0
	for i := 0; i < len(line); i++ {
		switch ch := line[i]; {
		case ch == '\\' && inQ && i+1 < len(line):
			i++
		case ch == '"':
			inQ = !inQ
		case ch == ',' && !inQ:
			opts = append(opts, line[start:i])
			start = i + 1
		case (ch == ' ' || ch == '\t') && !inQ:
			return append(opts, line[start:i]), strings.TrimSpace(line[i:])
		}
	}
	return append(opts, line[start:]), ""
}

// ParseAuthorizedKey parses one authorized_keys line.
func ParseAuthorizedKey(line string) (SSHKey, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return SSHKey{}, false
	}
	var opts []string
	if f := strings.Fields(line); len(f) > 0 && !keyTypeRe.MatchString(f[0]) {
		opts, line = splitOptions(line)
	}
	f := strings.Fields(line)
	if len(f) < 2 || !keyTypeRe.MatchString(f[0]) {
		return SSHKey{}, false
	}
	blob, err := base64.StdEncoding.DecodeString(f[1])
	if err != nil || len(blob) == 0 {
		return SSHKey{}, false
	}
	sum := sha256.Sum256(blob)
	k := SSHKey{Type: f[0], Fingerprint: "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:]), Bits: keyBits(f[0], blob)}
	if len(f) > 2 {
		k.Comment = trunc(strings.Join(f[2:], " "), 200)
	}
	for i, o := range opts {
		if i == 20 {
			break
		}
		k.Options = append(k.Options, trunc(o, 200))
	}
	return k, true
}

// sshString reads an SSH wire-format string (uint32 length + bytes).
func sshString(b []byte) ([]byte, []byte, bool) {
	if len(b) < 4 {
		return nil, nil, false
	}
	n := binary.BigEndian.Uint32(b)
	if uint64(len(b)-4) < uint64(n) {
		return nil, nil, false
	}
	return b[4 : 4+n], b[4+n:], true
}

func keyBits(typ string, blob []byte) int {
	switch {
	case strings.Contains(typ, "ed25519"):
		return 256
	case strings.HasPrefix(typ, "ecdsa-sha2-nistp"):
		n, _ := strconv.Atoi(strings.TrimPrefix(typ, "ecdsa-sha2-nistp"))
		return n
	case strings.HasPrefix(typ, "sk-ecdsa"):
		return 256
	case typ == "ssh-rsa" || typ == "ssh-dss":
		_, rest, ok := sshString(blob) // key type
		if !ok {
			return 0
		}
		first, rest, ok := sshString(rest) // rsa: e, dss: p
		if !ok {
			return 0
		}
		v := first
		if typ == "ssh-rsa" {
			if v, _, ok = sshString(rest); !ok { // rsa: n
				return 0
			}
		}
		for len(v) > 0 && v[0] == 0 {
			v = v[1:]
		}
		if len(v) == 0 {
			return 0
		}
		bits := len(v) * 8
		for b := v[0]; b&0x80 == 0; b <<= 1 {
			bits--
		}
		return bits
	}
	return 0
}

func (c *Collector) sshKeys(s *Snapshot) error {
	users, err := c.passwd()
	if err != nil {
		return err
	}
	seenHome := map[string]bool{}
	for _, u := range users {
		if u.home == "" || u.home == "/" || u.home == "/nonexistent" || seenHome[u.home+"\x00"+u.name] {
			continue
		}
		seenHome[u.home+"\x00"+u.name] = true
		for _, name := range []string{"authorized_keys", "authorized_keys2"} {
			file := filepath.Join(u.home, ".ssh", name)
			b, err := c.read(file)
			if err != nil {
				continue
			}
			sc := bufio.NewScanner(bytes.NewReader(b))
			sc.Buffer(make([]byte, 64*1024), 1<<20)
			for sc.Scan() {
				k, ok := ParseAuthorizedKey(sc.Text())
				if !ok {
					continue
				}
				k.User, k.File = u.name, file
				s.put(ModSSHKeys, u.name+"/"+k.Fingerprint, k)
			}
		}
	}
	return nil
}

/* ---------------- firewall ---------------- */

// Firewall summarises the ruleset without sending it: tool, hash, count, input policy.
type Firewall struct {
	Tool        string `json:"tool"`
	RulesHash   string `json:"rulesHash,omitempty"`
	RuleCount   int    `json:"ruleCount"`
	InputPolicy string `json:"inputPolicy,omitempty"`
	UFWEnabled  bool   `json:"ufwEnabled,omitempty"`
}

var (
	nftCounterRe  = regexp.MustCompile(`\s*counter packets \d+ bytes \d+`)
	iptCounterRe  = regexp.MustCompile(`\[\d+:\d+\]`)
	nftInputRe    = regexp.MustCompile(`hook input[^;]*;[^;]*policy (\w+);`)
	iptInputRe    = regexp.MustCompile(`(?m)^:INPUT (\w+)`)
	nftRuleLineRe = regexp.MustCompile(`(?m)^\s+(?:[a-z@].*\s)?(accept|drop|reject|jump \S+|goto \S+|return|masquerade|dnat.*|snat.*)\s*(comment ".*")?$`)
)

func hashText(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func (c *Collector) firewall(ctx context.Context, s *Snapshot) error {
	fw := Firewall{Tool: "none"}
	if b, err := c.read("/etc/ufw/ufw.conf"); err == nil {
		fw.UFWEnabled = regexp.MustCompile(`(?m)^ENABLED=yes`).Match(b)
	}
	if out, err := c.run(ctx, "nft", "list", "ruleset"); err == nil && len(bytes.TrimSpace(out)) > 0 {
		text := nftCounterRe.ReplaceAllString(string(out), "")
		fw.Tool, fw.RulesHash, fw.RuleCount = "nftables", hashText(text), len(nftRuleLineRe.FindAllString(text, -1))
		if m := nftInputRe.FindStringSubmatch(text); m != nil {
			fw.InputPolicy = m[1]
		}
	} else if out, err := c.run(ctx, "iptables-save"); err == nil && len(bytes.TrimSpace(out)) > 0 {
		var kept []string
		for _, l := range strings.Split(string(out), "\n") {
			if !strings.HasPrefix(l, "#") {
				kept = append(kept, iptCounterRe.ReplaceAllString(l, ""))
			}
		}
		text := strings.Join(kept, "\n")
		fw.Tool, fw.RulesHash = "iptables", hashText(text)
		for _, l := range kept {
			if strings.HasPrefix(l, "-A ") {
				fw.RuleCount++
			}
		}
		if m := iptInputRe.FindStringSubmatch(text); m != nil {
			fw.InputPolicy = strings.ToLower(m[1])
		}
	}
	s.put(ModFirewall, "firewall", fw)
	return nil
}

/* ---------------- scheduled tasks ---------------- */

// Scheduled is a cron entry or a systemd timer. Cron command lines are never sent:
// only the program (first word) and a hash of the whole line.
type Scheduled struct {
	Source   string `json:"source"`
	User     string `json:"user,omitempty"`
	Schedule string `json:"schedule,omitempty"`
	Program  string `json:"program,omitempty"`
	LineHash string `json:"lineHash,omitempty"`
	State    string `json:"state,omitempty"`
}

var cronEnvRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*\s*=`)

func (c *Collector) cronFile(s *Snapshot, file string, withUser bool, owner string) {
	b, err := c.read(file)
	if err != nil {
		return
	}
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") || cronEnvRe.MatchString(l) {
			continue
		}
		f := strings.Fields(l)
		n := 5
		if strings.HasPrefix(f[0], "@") {
			n = 1
		}
		if withUser {
			n++
		}
		if len(f) <= n {
			continue
		}
		e := Scheduled{Source: file, User: owner, Schedule: strings.Join(f[:min(n, len(f))], " "), Program: trunc(f[n], 200), LineHash: hashText(l)[:16]}
		if withUser {
			e.Schedule, e.User = strings.Join(f[:n-1], " "), f[n-1]
		}
		s.put(ModScheduled, "cron:"+file+"#"+e.LineHash, e)
	}
}

func (c *Collector) scheduled(ctx context.Context, s *Snapshot) error {
	c.cronFile(s, "/etc/crontab", true, "")
	for _, dir := range []struct {
		path     string
		withUser bool
	}{{"/etc/cron.d", true}, {"/var/spool/cron/crontabs", false}, {"/var/spool/cron", false}} {
		ents, _ := os.ReadDir(c.path(dir.path))
		for _, e := range ents {
			if e.Type().IsRegular() && !strings.HasPrefix(e.Name(), ".") {
				owner := ""
				if !dir.withUser {
					owner = e.Name()
				}
				c.cronFile(s, dir.path+"/"+e.Name(), dir.withUser, owner)
			}
		}
	}
	if out, err := c.run(ctx, "systemctl", "list-unit-files", "--type=timer", "--no-legend", "--no-pager"); err == nil {
		for _, l := range strings.Split(string(out), "\n") {
			if f := strings.Fields(l); len(f) >= 2 && strings.HasSuffix(f[0], ".timer") {
				s.put(ModScheduled, "timer:"+f[0], Scheduled{Source: "systemd", Program: f[0], State: f[1]})
			}
		}
	}
	return nil
}
