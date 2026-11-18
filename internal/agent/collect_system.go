package agent

import (
	"context"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

/* ---------------- system: boot, reboot, updates ---------------- */

// Update is a pending package update.
type Update struct {
	Name     string `json:"name"`
	Version  string `json:"version,omitempty"`
	Security bool   `json:"security"`
}

// SystemState is the update and reboot state. Package lists are read from the local package
// manager cache (the agent never refreshes it – that is the job of the system's own timers).
type SystemState struct {
	BootedAt        string   `json:"bootedAt,omitempty"`
	RebootRequired  *bool    `json:"rebootRequired"`
	PackageManager  string   `json:"packageManager,omitempty"`
	UpdatesPending  *int     `json:"updatesPending"`
	SecurityUpdates *int     `json:"securityUpdates"`
	AutoUpdates     *bool    `json:"autoUpdates"`
	Updates         []Update `json:"updates,omitempty"`
}

// systemEvery limits how often the (comparatively expensive) update check runs.
const systemEvery = time.Hour

var aptInst = regexp.MustCompile(`^Inst (\S+) (?:\[[^\]]*\] )?\((\S+) ([^)]*)\)`)

// parseAptSimulation reads "apt-get -s upgrade" output.
func parseAptSimulation(out string) []Update {
	var ups []Update
	for _, l := range strings.Split(out, "\n") {
		m := aptInst.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		ups = append(ups, Update{Name: trunc(m[1], 200), Version: trunc(m[2], 200), Security: strings.Contains(strings.ToLower(m[3]), "security")})
	}
	return ups
}

func boolp(v bool) *bool { return &v }
func intp(v int) *int    { return &v }

func (c *Collector) systemState(ctx context.Context) SystemState {
	st := SystemState{}
	if b, err := c.read("/proc/stat"); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if v, ok := strings.CutPrefix(l, "btime "); ok {
				if n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil {
					st.BootedAt = time.Unix(n, 0).UTC().Format(time.RFC3339)
				}
			}
		}
	}
	if c.exists("/run/reboot-required") || c.exists("/var/run/reboot-required") {
		st.RebootRequired = boolp(true)
	}
	var ups []Update
	switch {
	case c.exists("/usr/bin/apt-get"):
		st.PackageManager = "apt"
		if st.RebootRequired == nil {
			st.RebootRequired = boolp(false)
		}
		out, err := c.run(ctx, "apt-get", "-s", "-o", "Debug::NoLocking=1", "-o", "Dir::Cache::pkgcache=", "-o", "Dir::Cache::srcpkgcache=", "upgrade")
		if err == nil {
			ups = parseAptSimulation(string(out))
			st.UpdatesPending = intp(len(ups))
		}
		au, _ := c.read("/etc/apt/apt.conf.d/20auto-upgrades")
		st.AutoUpdates = boolp(regexp.MustCompile(`Unattended-Upgrade\s+"1"`).Match(au) && c.exists("/usr/bin/unattended-upgrade"))
	case c.exists("/usr/bin/dnf") || c.exists("/usr/bin/yum"):
		pm := "dnf"
		if !c.exists("/usr/bin/dnf") {
			pm = "yum"
		}
		st.PackageManager = pm
		if out, err := c.run(ctx, pm, "-q", "-C", "list", "--upgrades"); err == nil {
			for _, l := range strings.Split(string(out), "\n") {
				f := strings.Fields(l)
				if len(f) >= 3 && strings.Contains(f[0], ".") && !strings.HasPrefix(l, " ") && !strings.HasPrefix(f[0], "Available") {
					ups = append(ups, Update{Name: trunc(f[0], 200), Version: trunc(f[1], 200)})
				}
			}
			st.UpdatesPending = intp(len(ups))
			if sec, err := c.run(ctx, pm, "-q", "-C", "updateinfo", "list", "--security"); err == nil {
				var pk []string
				for _, l := range strings.Split(string(sec), "\n") {
					if f := strings.Fields(l); len(f) >= 3 {
						pk = append(pk, f[len(f)-1])
					}
				}
				for i := range ups {
					base := ups[i].Name
					if j := strings.LastIndex(base, "."); j > 0 {
						base = base[:j]
					}
					for _, p := range pk {
						if strings.HasPrefix(p, base+"-") {
							ups[i].Security = true
							break
						}
					}
				}
			}
		}
		_, err1 := c.run(ctx, "systemctl", "is-enabled", "dnf-automatic-install.timer")
		_, err2 := c.run(ctx, "systemctl", "is-enabled", "dnf-automatic.timer")
		st.AutoUpdates = boolp(err1 == nil || err2 == nil)
		if st.RebootRequired == nil {
			if _, err := c.run(ctx, "needs-restarting", "-r"); err == nil {
				st.RebootRequired = boolp(false)
			} else if strings.Contains(err.Error(), "exit status 1") {
				st.RebootRequired = boolp(true)
			}
		}
	}
	if st.UpdatesPending != nil {
		n := 0
		for _, u := range ups {
			if u.Security {
				n++
			}
		}
		st.SecurityUpdates = intp(n)
	}
	sort.SliceStable(ups, func(i, j int) bool {
		if ups[i].Security != ups[j].Security {
			return ups[i].Security
		}
		return ups[i].Name < ups[j].Name
	})
	if len(ups) > 50 {
		ups = ups[:50]
	}
	st.Updates = ups
	return st
}

func (c *Collector) system(ctx context.Context, s *Snapshot) error {
	now := c.now()
	if c.sysCache == nil || now.Sub(c.sysAt) >= systemEvery {
		st := c.systemState(ctx)
		c.sysCache, c.sysAt = &st, now
	}
	s.put(ModSystem, "system", *c.sysCache)
	return nil
}

/* ---------------- sshd: effective server settings ---------------- */

// sshdKeys are the effective settings sent from "sshd -T" (never host keys or file contents).
var sshdKeys = map[string]bool{
	"port": true, "permitrootlogin": true, "passwordauthentication": true, "permitemptypasswords": true,
	"pubkeyauthentication": true, "kbdinteractiveauthentication": true, "challengeresponseauthentication": true,
	"x11forwarding": true, "maxauthtries": true, "maxsessions": true, "maxstartups": true, "logingracetime": true,
	"clientaliveinterval": true, "clientalivecountmax": true, "allowtcpforwarding": true, "allowagentforwarding": true,
	"permittunnel": true, "gatewayports": true, "hostbasedauthentication": true, "ignorerhosts": true,
	"permituserenvironment": true, "usepam": true, "loglevel": true, "ciphers": true, "macs": true,
	"kexalgorithms": true, "allowusers": true, "allowgroups": true, "denyusers": true, "denygroups": true,
	"banner": true, "strictmodes": true, "disableforwarding": true,
}

// parseSshdT reads "sshd -T" output into the selected settings (repeated keys joined by a space).
func parseSshdT(out string) map[string]string {
	m := map[string]string{}
	for _, l := range strings.Split(out, "\n") {
		k, v, _ := strings.Cut(strings.TrimSpace(l), " ")
		k = strings.ToLower(k)
		if !sshdKeys[k] {
			continue
		}
		v = trunc(strings.TrimSpace(v), 1000)
		if prev, ok := m[k]; ok {
			m[k] = trunc(prev+" "+v, 1000)
		} else {
			m[k] = v
		}
	}
	return m
}

func (c *Collector) sshd(ctx context.Context, s *Snapshot) error {
	if !c.exists("/usr/sbin/sshd") && !c.exists("/usr/bin/sshd") {
		return nil
	}
	out, err := c.run(ctx, "sshd", "-T")
	if err != nil {
		return err
	}
	if m := parseSshdT(string(out)); len(m) > 0 {
		s.put(ModSSHD, "sshd", m)
	}
	return nil
}
