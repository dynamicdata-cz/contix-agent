package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func item[T any](t *testing.T, s *Snapshot, module, key string) T {
	t.Helper()
	var v T
	raw, ok := s.Modules[module][key]
	if !ok {
		t.Fatalf("%s/%s missing (have %v, errors %v)", module, key, keysOf(s.Modules[module]), s.Errors)
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func keysOf(m map[string]json.RawMessage) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

const inspectWeb = `{
  "Id": "4f0c1b2a3d4e5f60718293a4b5c6d7e8f9",
  "Name": "/web",
  "Created": "2026-11-01T10:00:00Z",
  "Image": "sha256:abcdef0123456789abcdef",
  "State": {"Status": "running", "StartedAt": "2026-11-17T08:00:00Z", "Health": {"Status": "healthy"}},
  "RestartCount": 2,
  "AppArmorProfile": "docker-default",
  "Config": {"Image": "nginx:1.27", "User": "", "Env": ["SECRET=x"], "Cmd": ["nginx", "-g", "daemon off;"],
    "Labels": {"com.docker.compose.project": "shop", "com.docker.compose.service": "web", "other": "x"},
    "Healthcheck": {"Test": ["CMD", "curl", "-f", "http://localhost"]}},
  "HostConfig": {"Privileged": false, "ReadonlyRootfs": true, "NetworkMode": "host", "PidMode": "", "IpcMode": "private",
    "CapAdd": ["NET_ADMIN"], "CapDrop": ["ALL"], "SecurityOpt": ["no-new-privileges:true", "seccomp=unconfined"],
    "Memory": 536870912, "NanoCpus": 1500000000, "PidsLimit": 100, "RestartPolicy": {"Name": "unless-stopped"},
    "Devices": [{"PathOnHost": "/dev/fuse"}]},
  "NetworkSettings": {"Ports": {"80/tcp": [{"HostIp": "", "HostPort": "8080"}], "443/tcp": null}},
  "Mounts": [{"Type": "bind", "Source": "/var/run/docker.sock", "Destination": "/var/run/docker.sock", "RW": true},
             {"Type": "volume", "Name": "data", "Source": "/var/lib/docker/volumes/data/_data", "Destination": "/data", "RW": true}]
}`

func fakeEngine(paths map[string]string) func(context.Context, string) ([]byte, error) {
	return func(_ context.Context, p string) ([]byte, error) {
		if v, ok := paths[p]; ok {
			return []byte(v), nil
		}
		return nil, errors.New("not found")
	}
}

func TestContainersFromEngine(t *testing.T) {
	root := t.TempDir()
	writeFiles(t, root, map[string]string{
		"/etc/group":              "root:x:0:\ndocker:x:998:alice,bob\n",
		"/etc/docker/daemon.json": `{"icc": false, "no-new-privileges": true, "hosts": ["unix:///var/run/docker.sock", "tcp://0.0.0.0:2375"]}`,
	})
	c := &Collector{Root: root, EngineGet: fakeEngine(map[string]string{
		"/containers/json?all=1":                              `[{"Id":"4f0c1b2a3d4e5f60718293a4b5c6d7e8f9"}]`,
		"/containers/4f0c1b2a3d4e5f60718293a4b5c6d7e8f9/json": inspectWeb,
		"/images/json": `[{"Id":"sha256:abcdef0123456789abcdef","RepoTags":["nginx:1.27","<none>:<none>"],"Created":1700000000,"Size":1234}]`,
		"/version":     `{"Version":"27.3.1"}`,
		"/info":        `{"SecurityOptions":["name=apparmor","name=seccomp,profile=builtin"],"LiveRestoreEnabled":false,"LoggingDriver":"json-file","CgroupVersion":"2"}`,
	})}
	s := c.Collect(context.Background(), []string{ModContainers, ModImages, ModEngine})
	if len(s.Errors) > 0 {
		t.Fatal(s.Errors)
	}
	ct := item[Container](t, s, ModContainers, "web")
	if ct.ID != "4f0c1b2a3d4e" || ct.Image != "nginx:1.27" || ct.ImageID != "abcdef012345" || ct.State != "running" || ct.Health != "healthy" {
		t.Fatalf("basic fields: %+v", ct)
	}
	if !ct.ReadOnlyRootfs || !ct.NoNewPrivs || ct.NetworkMode != "host" || ct.Restart != "unless-stopped" || ct.CPULimit != 1.5 || ct.PidsLimit != 100 || !ct.Healthcheck {
		t.Fatalf("security fields: %+v", ct)
	}
	if len(ct.Ports) != 1 || ct.Ports[0] != "0.0.0.0:8080->80/tcp" {
		t.Fatalf("ports: %v", ct.Ports)
	}
	if len(ct.Mounts) != 2 || ct.Mounts[0].Destination != "/data" || ct.Mounts[0].Source != "data" || ct.Mounts[1].Source != "/var/run/docker.sock" {
		t.Fatalf("mounts: %+v", ct.Mounts)
	}
	if ct.Project != "shop" || ct.Service != "web" {
		t.Fatalf("compose: %+v", ct)
	}
	raw := string(s.Modules[ModContainers]["web"])
	for _, secret := range []string{"SECRET", "daemon off", "other"} {
		if strings.Contains(raw, secret) {
			t.Fatalf("container item leaks %q: %s", secret, raw)
		}
	}
	im := item[Image](t, s, ModImages, "abcdef012345")
	if len(im.Tags) != 1 || im.Tags[0] != "nginx:1.27" || im.Created != "2023-11-14T22:13:20Z" {
		t.Fatalf("image: %+v", im)
	}
	e := item[Engine](t, s, ModEngine, "engine")
	if e.Version != "27.3.1" || e.ICC == nil || *e.ICC || !e.NoNewPrivileges || len(e.TCPHosts) != 1 || e.LoggingDriver != "json-file" {
		t.Fatalf("engine: %+v", e)
	}
	if strings.Join(e.GroupMembers, ",") != "alice,bob" {
		t.Fatalf("docker group: %v", e.GroupMembers)
	}
}

func TestNoEngineIsNotAnError(t *testing.T) {
	c := &Collector{Root: t.TempDir()}
	s := c.Collect(context.Background(), []string{ModContainers, ModImages, ModEngine})
	if len(s.Errors) > 0 || len(s.Modules[ModContainers]) != 0 || len(s.Modules[ModEngine]) != 0 {
		t.Fatalf("no engine: %+v", s)
	}
}

func TestParseAptSimulation(t *testing.T) {
	out := `NOTE: This is only a simulation!
Inst libssl3 [3.0.2-0ubuntu1.15] (3.0.2-0ubuntu1.18 Ubuntu:22.04/jammy-updates, Ubuntu:22.04/jammy-security [amd64])
Inst tzdata [2024a-0ubuntu0.22.04] (2024b-0ubuntu0.22.04 Ubuntu:22.04/jammy-updates [all])
Conf libssl3 (3.0.2-0ubuntu1.18 Ubuntu:22.04/jammy-updates [amd64])`
	ups := parseAptSimulation(out)
	if len(ups) != 2 || !ups[0].Security || ups[0].Version != "3.0.2-0ubuntu1.18" || ups[1].Security {
		t.Fatalf("%+v", ups)
	}
}

func TestSystemStateIsCached(t *testing.T) {
	root := t.TempDir()
	writeFiles(t, root, map[string]string{
		"/usr/bin/apt-get":                    "",
		"/usr/bin/unattended-upgrade":         "",
		"/etc/apt/apt.conf.d/20auto-upgrades": "APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";\n",
		"/run/reboot-required":                "",
		"/proc/stat":                          "cpu 1 2 3\nbtime 1763366400\n",
	})
	calls := 0
	now := time.Date(2026, 11, 18, 8, 0, 0, 0, time.UTC)
	c := &Collector{Root: root, Now: func() time.Time { return now }, Exec: func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name == "apt-get" {
			calls++
			return []byte("Inst openssh-server [1] (2 Ubuntu:22.04/jammy-security [amd64])\n"), nil
		}
		return nil, errors.New("unavailable")
	}}
	s := c.Collect(context.Background(), []string{ModSystem})
	st := item[SystemState](t, s, ModSystem, "system")
	if st.PackageManager != "apt" || st.RebootRequired == nil || !*st.RebootRequired || *st.UpdatesPending != 1 || *st.SecurityUpdates != 1 || !*st.AutoUpdates || st.BootedAt != "2025-11-17T08:00:00Z" {
		t.Fatalf("%+v", st)
	}
	now = now.Add(30 * time.Minute)
	c.Collect(context.Background(), []string{ModSystem})
	if calls != 1 {
		t.Fatalf("update check ran %d times within an hour", calls)
	}
	now = now.Add(31 * time.Minute)
	c.Collect(context.Background(), []string{ModSystem})
	if calls != 2 {
		t.Fatalf("update check not repeated after an hour (%d)", calls)
	}
}

func TestParseSshdT(t *testing.T) {
	m := parseSshdT("port 22\nport 2222\npermitrootlogin without-password\nPasswordAuthentication no\nhostkey /etc/ssh/ssh_host_ed25519_key\nciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com\n")
	if m["port"] != "22 2222" || m["permitrootlogin"] != "without-password" || m["passwordauthentication"] != "no" || !strings.Contains(m["ciphers"], "chacha20") {
		t.Fatalf("%v", m)
	}
	if _, ok := m["hostkey"]; ok {
		t.Fatal("host key path must not be sent")
	}
}

func TestHardeningFacts(t *testing.T) {
	root := t.TempDir()
	writeFiles(t, root, map[string]string{
		"/proc/sys/net/ipv4/ip_forward":       "0\n",
		"/proc/sys/kernel/randomize_va_space": "2\n",
		"/proc/1/mountinfo": "22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n" +
			"30 22 0:27 / /tmp rw,nosuid,nodev,noexec,relatime shared:2 - tmpfs tmpfs rw\n" +
			"31 22 0:28 / /dev/shm rw,nosuid,nodev shared:3 - tmpfs tmpfs rw\n",
		"/etc/shadow":                             "root:$6$abc:19000:0:99999:7:::\nnopw::19000:0:99999:7:::\nlocked:!:19000::::::\n",
		"/etc/login.defs":                         "# comment\nPASS_MAX_DAYS\t99999\nUMASK 022\nENCRYPT_METHOD YESCRYPT\n",
		"/etc/security/pwquality.conf":            "# minlen = 8\nminlen = 14\n",
		"/etc/pam.d/common-auth":                  "auth required pam_faillock.so preauth\n",
		"/etc/pam.d/common-password":              "password requisite pam_pwquality.so retry=3\n",
		"/etc/sudoers":                            "root ALL=(ALL:ALL) ALL\n%admin ALL=(ALL) ALL\n# deploy ALL=NOPASSWD: ALL\n",
		"/etc/sudoers.d/ci":                       "ci ALL=(ALL) NOPASSWD: /usr/bin/systemctl\n",
		"/etc/modprobe.d/cis.conf":                "install usb-storage /bin/false\nblacklist cramfs\n",
		"/proc/modules":                           "sctp 1 0 - Live 0x0\n",
		"/sys/module/apparmor/parameters/enabled": "Y\n",
		"/sys/kernel/security/apparmor/profiles":  "/usr/sbin/cupsd (enforce)\nsnap.x (complain)\n/usr/bin/man (enforce)\n",
		"/boot/grub/grub.cfg":                     "set superusers=\"root\"\npassword_pbkdf2 root grub.pbkdf2.sha512.10000.ABC\n",
		"/etc/systemd/journald.conf":              "[Journal]\nStorage=persistent\n",
		"/etc/rsyslog.d/50-remote.conf":           "*.* @@logs.example:514\n",
		"/etc/audit/rules.d/cis.rules":            "-w /etc/passwd -p wa -k identity\n-a always,exit -F arch=b64 -S adjtimex -k time\n",
		"/etc/issue.net":                          "Ubuntu 22.04 LTS\n",
	})
	c := &Collector{Root: root}
	s := c.Collect(context.Background(), []string{ModHardening})
	if len(s.Errors) > 0 {
		t.Fatal(s.Errors)
	}
	want := map[string]string{
		"sysctl.net.ipv4.ip_forward":       "0",
		"sysctl.kernel.randomize_va_space": "2",
		"mount./tmp":                       "noexec,nodev,nosuid,rw",
		"mount./dev/shm":                   "nodev,nosuid,rw",
		"mount./var/tmp":                   "-",
		"accounts.emptyPassword":           "nopw",
		"logindefs.PASS_MAX_DAYS":          "99999",
		"logindefs.UMASK":                  "022",
		"pwquality.minlen":                 "14",
		"pam.lockout":                      "faillock",
		"pam.pwquality":                    "true",
		"sudo.nopasswd":                    "ci",
		"module.usb_storage":               "blocked",
		"module.cramfs":                    "blocked",
		"module.sctp":                      "loaded",
		"module.dccp":                      "allowed",
		"mac.apparmor":                     "enabled enforce=2 complain=1",
		"mac.selinux":                      "absent",
		"boot.password":                    "true",
		"journald.storage":                 "persistent",
		"syslog.remote":                    "true",
		"audit.rules":                      "2",
		"banner.osInfo":                    "true",
	}
	for k, v := range want {
		got := item[Fact](t, s, ModHardening, k).V
		// mount options are sorted alphabetically
		if strings.HasPrefix(k, "mount.") && v != "-" {
			v = sortOpts(v)
		}
		if got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	all, _ := json.Marshal(s.Modules[ModHardening])
	if strings.Contains(string(all), "$6$abc") || strings.Contains(string(all), "pbkdf2.sha512") {
		t.Fatal("hardening facts leak secrets")
	}
}

func sortOpts(v string) string {
	f := strings.Split(v, ",")
	for i := range f {
		for j := i + 1; j < len(f); j++ {
			if f[j] < f[i] {
				f[i], f[j] = f[j], f[i]
			}
		}
	}
	return strings.Join(f, ",")
}

func TestEngineOverUnixSocket(t *testing.T) {
	root, err := os.MkdirTemp("/tmp", "eng")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	if err := os.MkdirAll(filepath.Join(root, "run"), 0o755); err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("unix", filepath.Join(root, "run/docker.sock"))
	if err != nil {
		t.Fatal(err)
	}
	var methods []string
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		methods = append(methods, r.Method)
		switch r.URL.Path {
		case "/version":
			_, _ = w.Write([]byte(`{"Version":"27.0.0"}`))
		case "/info":
			_, _ = w.Write([]byte(`{"SecurityOptions":["name=rootless"]}`))
		default:
			http.NotFound(w, r)
		}
	})}
	go func() { _ = srv.Serve(l) }()
	defer srv.Close()
	c := &Collector{Root: root}
	s := c.Collect(context.Background(), []string{ModEngine})
	e := item[Engine](t, s, ModEngine, "engine")
	if e.Version != "27.0.0" || !e.Rootless || e.Socket != "/run/docker.sock" {
		t.Fatalf("%+v", e)
	}
	for _, m := range methods {
		if m != http.MethodGet {
			t.Fatalf("engine API used with %s", m)
		}
	}
}
