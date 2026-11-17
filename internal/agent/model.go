// Package agent implements the read-only host agent: it collects host state, computes changes
// locally and sends signed messages to its zone concentrator. It never executes commands
// received from the network.
package agent

import (
	"bytes"
	"encoding/json"
	"sort"
)

// Module names (CONTIX ADR-177, agent modules).
const (
	ModPorts     = "ports"
	ModServices  = "services"
	ModPackages  = "packages"
	ModAccounts  = "accounts"
	ModSSHKeys   = "ssh_keys"
	ModFirewall  = "firewall"
	ModScheduled = "scheduled"
)

// AllModules is the default set collected by the agent.
var AllModules = []string{ModPorts, ModServices, ModPackages, ModAccounts, ModSSHKeys, ModFirewall, ModScheduled}

// HostInfo identifies the host (sent in snapshots and hello messages).
type HostInfo struct {
	Hostname string   `json:"hostname"`
	HostID   string   `json:"hostId"`
	OS       string   `json:"os"`
	Kernel   string   `json:"kernel"`
	IPs      []string `json:"ips"`
	Uptime   int64    `json:"uptimeSeconds"`
}

// Snapshot is the full collected state: module -> item key -> item (normalized JSON).
// Module errors are reported separately so a missing tool does not look like "no items".
type Snapshot struct {
	Host    HostInfo                              `json:"host"`
	Modules map[string]map[string]json.RawMessage `json:"modules"`
	Errors  map[string]string                     `json:"errors,omitempty"`
}

// Change is one difference between two snapshots.
type Change struct {
	Module string          `json:"module"`
	Op     string          `json:"op"` // add | remove | modify
	Key    string          `json:"key"`
	From   json.RawMessage `json:"from,omitempty"`
	To     json.RawMessage `json:"to,omitempty"`
}

// put adds an item to a module.
func (s *Snapshot) put(module, key string, item any) {
	if s.Modules == nil {
		s.Modules = map[string]map[string]json.RawMessage{}
	}
	if s.Modules[module] == nil {
		s.Modules[module] = map[string]json.RawMessage{}
	}
	b, err := json.Marshal(item)
	if err != nil {
		return
	}
	s.Modules[module][key] = b
}

// Diff returns changes from old to new. Modules that failed in either snapshot are skipped,
// so a temporarily missing tool does not report every item as removed.
func Diff(old, cur *Snapshot) []Change {
	var out []Change
	mods := map[string]bool{}
	for m := range old.Modules {
		mods[m] = true
	}
	for m := range cur.Modules {
		mods[m] = true
	}
	names := make([]string, 0, len(mods))
	for m := range mods {
		names = append(names, m)
	}
	sort.Strings(names)
	for _, m := range names {
		if old.Errors[m] != "" || cur.Errors[m] != "" {
			continue
		}
		o, n := old.Modules[m], cur.Modules[m]
		keys := map[string]bool{}
		for k := range o {
			keys[k] = true
		}
		for k := range n {
			keys[k] = true
		}
		ks := make([]string, 0, len(keys))
		for k := range keys {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		for _, k := range ks {
			a, inOld := o[k]
			b, inNew := n[k]
			switch {
			case !inOld:
				out = append(out, Change{Module: m, Op: "add", Key: k, To: b})
			case !inNew:
				out = append(out, Change{Module: m, Op: "remove", Key: k, From: a})
			case !bytes.Equal(a, b):
				out = append(out, Change{Module: m, Op: "modify", Key: k, From: a, To: b})
			}
		}
	}
	return out
}
