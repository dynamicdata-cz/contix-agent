package concentrator

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"time"
)

// EnrollTokenPrefix marks zone enrollment tokens (created on the concentrator, never sent to CONTIX).
const EnrollTokenPrefix = "ctxe_"

// ErrBadToken is returned for unknown, expired or used-up enrollment tokens.
var ErrBadToken = errors.New("concentrator: invalid, expired or used-up enrollment token")

type enrollToken struct {
	Hash      string    `json:"hash"`
	ExpiresAt time.Time `json:"expiresAt"`
	UsesLeft  int       `json:"usesLeft"`
	CreatedAt time.Time `json:"createdAt"`
}

// AgentRecord is what the concentrator remembers about an enrolled agent.
type AgentRecord struct {
	PublicKey string    `json:"publicKey"`
	HostID    string    `json:"hostId"`
	Hostname  string    `json:"hostname"`
	Enrolled  time.Time `json:"enrolled"`
}

// Registry holds enrollment tokens and enrolled agents (tokens.json, agents.json).
type Registry struct {
	p      Paths
	mu     sync.Mutex
	tokens []enrollToken
	agents map[string]AgentRecord
}

// LoadRegistry reads tokens and agents from the state directory.
func LoadRegistry(p Paths) (*Registry, error) {
	r := &Registry{p: p, agents: map[string]AgentRecord{}}
	if err := readJSON(p.Tokens(), &r.tokens); err != nil {
		return nil, err
	}
	if err := readJSON(p.Agents(), &r.agents); err != nil {
		return nil, err
	}
	return r, nil
}

func tokenHash(t string) string {
	sum := sha256.Sum256([]byte(t))
	return hex.EncodeToString(sum[:])
}

// CreateToken issues an enrollment token for `uses` agents valid for ttl. Only its hash is stored.
func (r *Registry) CreateToken(uses int, ttl time.Duration) (string, error) {
	if uses < 1 || ttl <= 0 {
		return "", errors.New("concentrator: uses must be >= 1 and ttl > 0")
	}
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	tok := EnrollTokenPrefix + base64.RawURLEncoding.EncodeToString(b)
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.reloadTokens(); err != nil {
		return "", err
	}
	now := time.Now()
	kept := r.tokens[:0]
	for _, t := range r.tokens { // drop expired / used-up tokens
		if t.UsesLeft > 0 && t.ExpiresAt.After(now) {
			kept = append(kept, t)
		}
	}
	r.tokens = append(kept, enrollToken{Hash: tokenHash(tok), ExpiresAt: now.Add(ttl), UsesLeft: uses, CreatedAt: now})
	return tok, writeJSON(r.p.Tokens(), r.tokens, 0o600)
}

// CheckToken verifies a token without consuming it.
func (r *Registry) CheckToken(tok string, now time.Time) error {
	if !strings.HasPrefix(tok, EnrollTokenPrefix) {
		return ErrBadToken
	}
	h := tokenHash(tok)
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.reloadTokens(); err != nil {
		return err
	}
	for _, t := range r.tokens {
		if t.Hash == h && t.UsesLeft > 0 && t.ExpiresAt.After(now) {
			return nil
		}
	}
	return ErrBadToken
}

// ConsumeToken uses one enrollment of a token (after the enrollment succeeded).
func (r *Registry) ConsumeToken(tok string, now time.Time) error {
	h := tokenHash(tok)
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.reloadTokens(); err != nil {
		return err
	}
	for i, t := range r.tokens {
		if t.Hash == h && t.UsesLeft > 0 && t.ExpiresAt.After(now) {
			r.tokens[i].UsesLeft--
			return writeJSON(r.p.Tokens(), r.tokens, 0o600)
		}
	}
	return ErrBadToken
}

// reloadTokens re-reads tokens.json: tokens are created by a separate CLI process while the service runs.
func (r *Registry) reloadTokens() error {
	var t []enrollToken
	if err := readJSON(r.p.Tokens(), &t); err != nil {
		return err
	}
	r.tokens = t
	return nil
}

// PutAgent stores an enrolled agent. A re-enrolled host (new key = new CONTIX identity) replaces
// its previous entry, so the old certificate's agent ID is no longer accepted here either.
func (r *Registry) PutAgent(id string, a AgentRecord) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for old, rec := range r.agents {
		if rec.HostID == a.HostID && old != id {
			delete(r.agents, old)
		}
	}
	r.agents[id] = a
	return writeJSON(r.p.Agents(), r.agents, 0o600)
}

// AgentKey returns the signing key of an enrolled agent.
func (r *Registry) AgentKey(id string) (ed25519.PublicKey, bool) {
	r.mu.Lock()
	a, ok := r.agents[id]
	r.mu.Unlock()
	if !ok {
		return nil, false
	}
	k, err := base64.StdEncoding.DecodeString(a.PublicKey)
	if err != nil || len(k) != ed25519.PublicKeySize {
		return nil, false
	}
	return ed25519.PublicKey(k), true
}

// Agents returns the number of enrolled agents.
func (r *Registry) Agents() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.agents)
}
