package concentrator

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// API paths on CONTIX (ADR-177, /api/public/agent/v1).
const apiBase = "/api/public/agent/v1"

// Signed request headers and signing-string prefix; must match concentratorSigningString in CONTIX.
const (
	headerID        = "X-Contix-Concentrator"
	headerDate      = "X-Contix-Date"
	headerSignature = "X-Contix-Signature"
	signingPrefix   = "CONTIX-CONCENTRATOR-V1"
)

// SigningString returns the text the concentrator signs for every request to CONTIX.
func SigningString(method, path, date string, body []byte) string {
	sum := sha256.Sum256(body)
	return strings.Join([]string{signingPrefix, strings.ToUpper(method), path, date, hex.EncodeToString(sum[:])}, "\n")
}

// HTTPError is a non-2xx answer from CONTIX.
type HTTPError struct {
	Status int
	Body   string
}

func (e *HTTPError) Error() string { return fmt.Sprintf("contix: HTTP %d: %s", e.Status, e.Body) }

// Permanent reports whether retrying the same request cannot succeed (malformed or too large).
func (e *HTTPError) Permanent() bool {
	return e.Status == http.StatusBadRequest || e.Status == http.StatusRequestEntityTooLarge
}

// Client talks to CONTIX. Requests after registration are signed with the concentrator key.
type Client struct {
	BaseURL string
	ID      string
	Key     ed25519.PrivateKey
	HTTP    *http.Client
	Now     func() time.Time
}

// NewHTTPClient trusts the system roots plus an optional extra CA file (internal CONTIX CA).
func NewHTTPClient(caFile string) (*http.Client, error) {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("concentrator: no certificate in %s", caFile)
		}
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	return &http.Client{Transport: tr, Timeout: 60 * time.Second}, nil
}

func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *Client) do(ctx context.Context, path string, in, out any, signed bool) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	u, err := url.JoinPath(c.BaseURL, apiBase, path)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if signed {
		date := c.now().UTC().Format(time.RFC3339)
		sig := ed25519.Sign(c.Key, []byte(SigningString(http.MethodPost, req.URL.EscapedPath(), date, body)))
		req.Header.Set(headerID, c.ID)
		req.Header.Set(headerDate, date)
		req.Header.Set(headerSignature, base64.StdEncoding.EncodeToString(sig))
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return &HTTPError{Status: resp.StatusCode, Body: strings.TrimSpace(string(data))}
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

// RegisterResult is CONTIX's answer to a registration code.
type RegisterResult struct {
	ConcentratorID string `json:"concentratorId"`
	Zone           string `json:"zone"`
}

// Register exchanges the one-time code for a concentrator identity bound to pub.
func (c *Client) Register(ctx context.Context, code, hostname, version string, pub ed25519.PublicKey) (*RegisterResult, error) {
	var r RegisterResult
	in := map[string]string{"code": code, "publicKey": base64.StdEncoding.EncodeToString(pub), "hostname": hostname, "version": version}
	if err := c.do(ctx, "/register", in, &r, false); err != nil {
		return nil, err
	}
	return &r, nil
}

// AgentInfo is what the concentrator reports about an enrolling agent.
type AgentInfo struct {
	HostID    string `json:"hostId"`
	Hostname  string `json:"hostname"`
	OS        string `json:"os"`
	Version   string `json:"version"`
	PublicKey string `json:"publicKey"`
}

// AgentRegistration is CONTIX's decision about an agent.
type AgentRegistration struct {
	AgentID string `json:"agentId"`
	Status  string `json:"status"`
}

// RegisterAgent forwards an agent enrollment to CONTIX.
func (c *Client) RegisterAgent(ctx context.Context, a AgentInfo) (*AgentRegistration, error) {
	var r AgentRegistration
	if err := c.do(ctx, "/agents", a, &r, true); err != nil {
		return nil, err
	}
	return &r, nil
}

// BatchResult mirrors AgentBatchResult in CONTIX.
type BatchResult struct {
	Acks       map[string]uint64 `json:"acks"`
	Accepted   int               `json:"accepted"`
	Duplicates int               `json:"duplicates"`
	Rejected   []struct {
		Index  int    `json:"index"`
		Reason string `json:"reason"`
	} `json:"rejected"`
}

// SendBatch forwards signed agent messages exactly as received (never re-encoded).
func (c *Client) SendBatch(ctx context.Context, messages []json.RawMessage) (*BatchResult, error) {
	var r BatchResult
	if err := c.do(ctx, "/batches", map[string]any{"messages": messages}, &r, true); err != nil {
		return nil, err
	}
	return &r, nil
}

// Hello reports the concentrator's own state.
func (c *Client) Hello(ctx context.Context, status Status) error {
	return c.do(ctx, "/hello", status, nil, true)
}

// Status is the concentrator's self-report (no host data of agents).
type Status struct {
	Version       string `json:"version"`
	Hostname      string `json:"hostname"`
	UptimeSeconds int64  `json:"uptimeSeconds"`
	Agents        int    `json:"agents"`
	QueueFiles    int    `json:"queueFiles"`
	QueueBytes    int64  `json:"queueBytes"`
	LastForwardAt string `json:"lastForwardAt,omitempty"`
	LastError     string `json:"lastError,omitempty"`
	CACertExpires string `json:"caCertExpires,omitempty"`
}
