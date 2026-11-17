package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFiles(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for p, content := range files {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func sshStr(b []byte) []byte {
	out := make([]byte, 4+len(b))
	binary.BigEndian.PutUint32(out, uint32(len(b)))
	copy(out[4:], b)
	return out
}

func mpint(n *big.Int) []byte {
	b := n.Bytes()
	if len(b) > 0 && b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	return sshStr(b)
}

func ed25519Line(t *testing.T, comment string) (string, string) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	blob := append(sshStr([]byte("ssh-ed25519")), sshStr(pub)...)
	sum := sha256.Sum256(blob)
	return "ssh-ed25519 " + base64.StdEncoding.EncodeToString(blob) + " " + comment, "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

func rsaLine(t *testing.T, bits int) string {
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	blob := append(append(sshStr([]byte("ssh-rsa")), mpint(big.NewInt(int64(k.E)))...), mpint(k.N)...)
	return "ssh-rsa " + base64.StdEncoding.EncodeToString(blob)
}

func fakeExec(outputs map[string]string) func(context.Context, string, ...string) ([]byte, error) {
	return func(_ context.Context, name string, args ...string) ([]byte, error) {
		key := strings.Join(append([]string{name}, args...), " ")
		for k, v := range outputs {
			if strings.HasPrefix(key, k) {
				return []byte(v), nil
			}
		}
		return nil, errors.New("not found: " + name)
	}
}

func TestCollectFixtureHost(t *testing.T) {
	root := t.TempDir()
	edLine, edFP := ed25519Line(t, "jan@notebook")
	writeFiles(t, root, map[string]string{
		"/proc/sys/kernel/hostname":      "srv-app-01\n",
		"/proc/sys/kernel/osrelease":     "6.8.0-45-generic\n",
		"/proc/uptime":                   "3600.52 7000.10\n",
		"/etc/machine-id":                "0f1e2d3c4b5a69788796a5b4c3d2e1f0\n",
		"/etc/os-release":                "NAME=\"Ubuntu\"\nPRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\n",
		"/proc/net/tcp":                  "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1111 1 0\n   1: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2222 1 0\n   2: 0B00000A:D431 0101A8C0:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 3333 1 0\n",
		"/proc/net/tcp6":                 "  sl  local_address remote_address st\n   0: 00000000000000000000000000000000:01BB 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 4444 1 0\n",
		"/proc/net/udp":                  "  sl  local_address rem_address   st\n   0: 3500007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000   101        0 5555 2 0\n",
		"/proc/123/comm":                 "sshd\n",
		"/var/lib/dpkg/status":           "Package: openssh-server\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1:9.6p1-3ubuntu13\n\nPackage: removed-pkg\nStatus: deinstall ok config-files\nArchitecture: amd64\nVersion: 1.0\n\nPackage: nginx\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1.24.0-2\n",
		"/etc/passwd":                    "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\njan:x:1000:1000:Jan:/home/jan:/bin/bash\ntoor:x:0:0::/home/toor:/bin/sh\nnopw:x:1001:1001::/home/nopw:/bin/bash\n",
		"/etc/group":                     "root:x:0:\nsudo:x:27:jan\njan:x:1000:\n",
		"/etc/shadow":                    "root:!:19000:0:99999:7:::\ndaemon:*:19000:0:99999:7:::\njan:$6$salt$secrethashvalue:19000:0:99999:7:::\ntoor:$y$j9T$another$hash:19000::::::\nnopw::19000::::::\n",
		"/home/jan/.ssh/authorized_keys": "# my keys\n" + edLine + "\nfrom=\"10.0.0.0/8\",no-pty,command=\"/usr/bin/backup --to x\" " + rsaLine(t, 2048) + "\ngarbage line\n",
		"/etc/ufw/ufw.conf":              "ENABLED=yes\n",
		"/etc/crontab":                   "SHELL=/bin/sh\n17 * * * * root cd / && run-parts --report /etc/cron.hourly\n",
		"/etc/cron.d/backup":             "# backup\n0 2 * * * root /usr/local/bin/backup.sh --password=Hunter2\n",
		"/var/spool/cron/crontabs/jan":   "@reboot /home/jan/start.sh secret-token-123\n",
	})
	// socket inode 1111 belongs to pid 123 (sshd)
	if err := os.MkdirAll(filepath.Join(root, "/proc/123/fd"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("socket:[1111]", filepath.Join(root, "/proc/123/fd/3")); err != nil {
		t.Fatal(err)
	}
	nft := "table inet filter {\n\tchain input {\n\t\ttype filter hook input priority filter; policy drop;\n\t\tct state established,related accept\n\t\ttcp dport 22 counter packets 120 bytes 9000 accept\n\t}\n}\n"
	c := &Collector{Root: root, Exec: fakeExec(map[string]string{
		"systemctl list-units":                     "ssh.service loaded active running OpenBSD Secure Shell server\ncron.service loaded active running Regular background program processing daemon\nbad.service not-found inactive dead bad.service\n",
		"systemctl list-unit-files --type=service": "ssh.service enabled enabled\ncron.service enabled enabled\nnginx.service enabled enabled\ngetty@.service enabled enabled\n",
		"systemctl list-unit-files --type=timer":   "apt-daily.timer enabled enabled\n",
		"nft list ruleset":                         nft,
	})}
	s := c.Collect(context.Background(), AllModules)
	if len(s.Errors) != 0 {
		t.Fatalf("module errors: %v", s.Errors)
	}
	if s.Host.Hostname != "srv-app-01" || s.Host.HostID != "0f1e2d3c4b5a69788796a5b4c3d2e1f0" || s.Host.OS != "Ubuntu 24.04.1 LTS" || s.Host.Uptime != 3600 {
		t.Fatalf("host %+v", s.Host)
	}
	keys := func(m string) []string {
		var out []string
		for k := range s.Modules[m] {
			out = append(out, k)
		}
		return out
	}
	assertHas := func(m string, want ...string) {
		t.Helper()
		got := strings.Join(keys(m), " | ")
		for _, w := range want {
			if _, ok := s.Modules[m][w]; !ok {
				t.Errorf("%s: missing %q (have %s)", m, w, got)
			}
		}
	}
	assertHas(ModPorts, "tcp/0.0.0.0:22", "tcp/127.0.0.1:8080", "tcp/[::]:443", "udp/127.0.0.53:53")
	if len(s.Modules[ModPorts]) != 4 {
		t.Errorf("established connection reported as listener: %v", keys(ModPorts))
	}
	var p Port
	_ = json.Unmarshal(s.Modules[ModPorts]["tcp/0.0.0.0:22"], &p)
	if p.Process != "sshd" {
		t.Errorf("port 22 process %q", p.Process)
	}
	assertHas(ModPackages, "openssh-server:amd64", "nginx:amd64")
	if _, ok := s.Modules[ModPackages]["removed-pkg:amd64"]; ok {
		t.Error("removed package reported")
	}
	assertHas(ModServices, "ssh.service", "cron.service", "nginx.service")
	if _, ok := s.Modules[ModServices]["bad.service"]; ok {
		t.Error("not-found unit reported")
	}
	var root0, jan, nopw, daemon Account
	_ = json.Unmarshal(s.Modules[ModAccounts]["toor"], &root0)
	_ = json.Unmarshal(s.Modules[ModAccounts]["jan"], &jan)
	_ = json.Unmarshal(s.Modules[ModAccounts]["nopw"], &nopw)
	_ = json.Unmarshal(s.Modules[ModAccounts]["daemon"], &daemon)
	if !root0.Admin || root0.UID != 0 || !jan.Admin || !jan.Login || jan.Locked == nil || *jan.Locked || !nopw.NoPassword || daemon.Login || !*daemon.Locked {
		t.Errorf("accounts: toor %+v jan %+v nopw %+v daemon %+v", root0, jan, nopw, daemon)
	}
	assertHas(ModSSHKeys, "jan/"+edFP)
	if len(s.Modules[ModSSHKeys]) != 2 {
		t.Fatalf("ssh keys %v", keys(ModSSHKeys))
	}
	for _, raw := range s.Modules[ModSSHKeys] {
		var k SSHKey
		_ = json.Unmarshal(raw, &k)
		if k.Type == "ssh-rsa" && (k.Bits != 2048 || len(k.Options) != 3 || k.Options[2] != `command="/usr/bin/backup --to x"`) {
			t.Errorf("rsa key %+v", k)
		}
		if k.Type == "ssh-ed25519" && (k.Bits != 256 || k.Comment != "jan@notebook") {
			t.Errorf("ed25519 key %+v", k)
		}
	}
	var fw Firewall
	_ = json.Unmarshal(s.Modules[ModFirewall]["firewall"], &fw)
	if fw.Tool != "nftables" || fw.InputPolicy != "drop" || fw.RuleCount != 2 || !fw.UFWEnabled {
		t.Errorf("firewall %+v", fw)
	}
	assertHas(ModScheduled, "timer:apt-daily.timer")
	if len(s.Modules[ModScheduled]) != 4 {
		t.Errorf("scheduled %v", keys(ModScheduled))
	}

	// nothing secret leaves the host: no password hashes, no key material, no cron arguments
	all, _ := json.Marshal(s)
	for _, secret := range []string{"secrethashvalue", "$6$", "$y$", "Hunter2", "secret-token-123", "AAAAC3NzaC1lZDI1NTE5"} {
		if strings.Contains(string(all), secret) {
			t.Errorf("snapshot contains %q", secret)
		}
	}

	// firewall counters change all the time – the hash must not
	c.Exec = fakeExec(map[string]string{"nft list ruleset": strings.Replace(nft, "packets 120 bytes 9000", "packets 99999 bytes 123456", 1)})
	s2 := c.Collect(context.Background(), []string{ModFirewall})
	var fw2 Firewall
	_ = json.Unmarshal(s2.Modules[ModFirewall]["firewall"], &fw2)
	if fw2.RulesHash != fw.RulesHash {
		t.Error("firewall hash depends on packet counters")
	}
}

func TestDiff(t *testing.T) {
	a := &Snapshot{}
	a.put(ModPorts, "tcp/0.0.0.0:22", Port{Proto: "tcp", Address: "0.0.0.0", Port: 22, Process: "sshd"})
	a.put(ModPorts, "tcp/0.0.0.0:23", Port{Proto: "tcp", Address: "0.0.0.0", Port: 23, Process: "telnetd"})
	a.put(ModPackages, "nginx:amd64", Package{Name: "nginx", Version: "1.24.0", Arch: "amd64"})
	a.put(ModServices, "x.service", Service{Name: "x.service"})
	b := &Snapshot{Errors: map[string]string{ModServices: "systemctl missing"}}
	b.put(ModPorts, "tcp/0.0.0.0:22", Port{Proto: "tcp", Address: "0.0.0.0", Port: 22, Process: "sshd"})
	b.put(ModPorts, "tcp/0.0.0.0:8443", Port{Proto: "tcp", Address: "0.0.0.0", Port: 8443, Process: "contix-agent"})
	b.put(ModPackages, "nginx:amd64", Package{Name: "nginx", Version: "1.26.0", Arch: "amd64"})
	ch := Diff(a, b)
	got := []string{}
	for _, c := range ch {
		got = append(got, c.Module+" "+c.Op+" "+c.Key)
	}
	want := "packages modify nginx:amd64,ports remove tcp/0.0.0.0:23,ports add tcp/0.0.0.0:8443"
	if strings.Join(got, ",") != want {
		t.Fatalf("diff\n got  %v\n want %s", got, want)
	}
	if len(Diff(b, b)) != 0 {
		t.Fatal("diff of identical snapshots")
	}
}

func TestParseAuthorizedKeyRejects(t *testing.T) {
	for _, l := range []string{"", "# comment", "ssh-ed25519", "ssh-ed25519 !!!notbase64", "unknown-type AAAA comment"} {
		if _, ok := ParseAuthorizedKey(l); ok {
			t.Errorf("accepted %q", l)
		}
	}
}
