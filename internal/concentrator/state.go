// Package concentrator implements the zone concentrator: agent enrollment,
// mTLS listener, on-disk queue and signed forwarding to CONTIX.
package concentrator

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/dynamicdata-cz/contix-agent/internal/fsutil"
	"github.com/dynamicdata-cz/contix-agent/internal/identity"
)

// DefaultStateDir is where the systemd service keeps keys, certificates and the queue.
const DefaultStateDir = "/var/lib/contix-agent/concentrator"

// State is the persistent registration of a concentrator (state.json). It holds no secrets:
// private keys live in separate 0600 files next to it.
type State struct {
	URL            string `json:"url"`
	ConcentratorID string `json:"concentratorId"`
	Zone           string `json:"zone"`
	// CAFile optionally pins the CA that signed CONTIX's TLS certificate (empty = system roots).
	CAFile string `json:"caFile,omitempty"`
	// Listen is the agent-facing address (default ":8443").
	Listen string `json:"listen,omitempty"`
	// ServerNames are extra DNS names / IPs agents use to reach the concentrator (added to its certificate).
	ServerNames []string `json:"serverNames,omitempty"`
}

// Paths of files inside the state directory.
type Paths struct{ Dir string }

func (p Paths) State() string      { return filepath.Join(p.Dir, "state.json") }
func (p Paths) SigningKey() string { return filepath.Join(p.Dir, "signing.key") }
func (p Paths) CACert() string     { return filepath.Join(p.Dir, "zone-ca.crt") }
func (p Paths) CAKey() string      { return filepath.Join(p.Dir, "zone-ca.key") }
func (p Paths) ServerCert() string { return filepath.Join(p.Dir, "server.crt") }
func (p Paths) ServerKey() string  { return filepath.Join(p.Dir, "server.key") }
func (p Paths) Agents() string     { return filepath.Join(p.Dir, "agents.json") }
func (p Paths) Tokens() string     { return filepath.Join(p.Dir, "tokens.json") }
func (p Paths) Queue() string      { return filepath.Join(p.Dir, "queue") }

// ErrNotRegistered means `concentrator register` has not been run for this state directory.
var ErrNotRegistered = errors.New("concentrator: not registered (run: contix-agent concentrator register)")

// LoadState reads state.json and the signing key.
func LoadState(p Paths) (*State, ed25519.PrivateKey, error) {
	data, err := os.ReadFile(p.State())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, ErrNotRegistered
	}
	if err != nil {
		return nil, nil, err
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, nil, fmt.Errorf("concentrator: %s: %w", p.State(), err)
	}
	if s.URL == "" || s.ConcentratorID == "" {
		return nil, nil, ErrNotRegistered
	}
	key, err := identity.LoadKey(p.SigningKey())
	if err != nil {
		return nil, nil, err
	}
	return &s, key, nil
}

func writeJSON(path string, v any, mode os.FileMode) error { return fsutil.WriteJSON(path, v, mode) }

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	return fsutil.WriteFileAtomic(path, data, mode)
}

func readJSON(path string, v any) error { return fsutil.ReadJSON(path, v) }
