package agent

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dynamicdata-cz/contix-agent/internal/fsutil"
	"github.com/dynamicdata-cz/contix-agent/internal/identity"
)

// DefaultStateDir holds the agent's keys, certificates, last state and outbox.
const DefaultStateDir = "/var/lib/contix-agent-host"

// Paths of files inside the agent state directory.
type Paths struct{ Dir string }

func (p Paths) State() string      { return filepath.Join(p.Dir, "state.json") }
func (p Paths) SigningKey() string { return filepath.Join(p.Dir, "signing.key") }
func (p Paths) TLSKey() string     { return filepath.Join(p.Dir, "tls.key") }
func (p Paths) TLSCert() string    { return filepath.Join(p.Dir, "tls.crt") }
func (p Paths) CACert() string     { return filepath.Join(p.Dir, "ca.crt") }
func (p Paths) Seq() string        { return filepath.Join(p.Dir, "seq") }
func (p Paths) Last() string       { return filepath.Join(p.Dir, "last.json") }
func (p Paths) Outbox() string     { return filepath.Join(p.Dir, "outbox") }

// State is the agent's enrollment (state.json, no secrets).
type State struct {
	Concentrator  string    `json:"concentrator"`
	AgentID       string    `json:"agentId"`
	Status        string    `json:"status"`
	CAFingerprint string    `json:"caFingerprint"`
	EnrolledAt    time.Time `json:"enrolledAt"`
}

// ErrNotEnrolled means `agent enroll` has not been run.
var ErrNotEnrolled = errors.New("agent: not enrolled (run: contix-agent agent enroll)")

// LoadState reads state.json.
func LoadState(p Paths) (*State, error) {
	var s State
	if err := fsutil.ReadJSON(p.State(), &s); err != nil {
		return nil, err
	}
	if s.AgentID == "" || s.Concentrator == "" {
		return nil, ErrNotEnrolled
	}
	return &s, nil
}

func normFP(fp string) string {
	return strings.ToLower(strings.NewReplacer(":", "", " ", "").Replace(strings.TrimSpace(fp)))
}

func certFP(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}

// pinnedTLS trusts the concentrator only if its presented chain contains the CA with the
// pinned SHA-256 fingerprint and the server certificate verifies against that CA.
func pinnedTLS(fingerprint, serverName string) *tls.Config {
	want := normFP(fingerprint)
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		ServerName:         serverName,
		InsecureSkipVerify: true, // replaced by VerifyConnection below (pinning), never skipped
		VerifyConnection: func(cs tls.ConnectionState) error {
			var ca *x509.Certificate
			for _, c := range cs.PeerCertificates {
				if c.IsCA && certFP(c) == want {
					ca = c
				}
			}
			if ca == nil || len(cs.PeerCertificates) == 0 {
				return errors.New("agent: concentrator CA does not match the pinned fingerprint")
			}
			roots := x509.NewCertPool()
			roots.AddCert(ca)
			// verify the name we connected to (for an IP address no SNI is sent and cs.ServerName is empty)
			_, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{Roots: roots, DNSName: serverName})
			return err
		},
	}
}

// EnrollOptions are the inputs of `contix-agent agent enroll`.
type EnrollOptions struct {
	Concentrator  string // https://host:8443
	Token         string // ctxe_…
	CAFingerprint string // SHA-256 of the zone CA (hex)
	Version       string
	Force         bool
}

type enrollRequest struct {
	Token     string `json:"token"`
	HostID    string `json:"hostId"`
	Hostname  string `json:"hostname"`
	OS        string `json:"os"`
	Version   string `json:"version"`
	PublicKey string `json:"publicKey"`
	CSR       string `json:"csr"`
}

type enrollResponse struct {
	AgentID     string `json:"agentId"`
	Status      string `json:"status"`
	Certificate string `json:"certificate"`
	CA          string `json:"ca"`
}

// Enroll creates the agent keys, enrolls at the concentrator with a zone token and stores the
// client certificate. The concentrator is trusted only via the pinned CA fingerprint.
func Enroll(ctx context.Context, p Paths, c *Collector, o EnrollOptions) (*State, error) {
	if _, err := os.Stat(p.State()); err == nil && !o.Force {
		return nil, fmt.Errorf("agent: already enrolled (%s); use --force to enroll again", p.State())
	}
	u, err := url.Parse(strings.TrimRight(o.Concentrator, "/"))
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, errors.New("agent: --concentrator must be https://host:port")
	}
	if len(normFP(o.CAFingerprint)) != 64 {
		return nil, errors.New("agent: --ca-fingerprint must be the 64-hex-digit SHA-256 of the zone CA")
	}
	if err := os.MkdirAll(p.Dir, 0o700); err != nil {
		return nil, err
	}
	host := c.host()
	if host.HostID == "" {
		return nil, errors.New("agent: no stable host identity (/etc/machine-id)")
	}
	signKey, err := identity.GenerateSigningKey()
	if err != nil {
		return nil, err
	}
	tlsKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: host.Hostname}}, tlsKey)
	if err != nil {
		return nil, err
	}
	body, _ := json.Marshal(enrollRequest{
		Token: o.Token, HostID: host.HostID, Hostname: host.Hostname, OS: host.OS, Version: o.Version,
		PublicKey: base64.StdEncoding.EncodeToString(signKey.Public().(ed25519.PublicKey)),
		CSR:       string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})),
	})
	hc := &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{TLSClientConfig: pinnedTLS(o.CAFingerprint, u.Hostname())}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String()+"/v1/enroll", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("agent: enrollment refused: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	var er enrollResponse
	if err := json.Unmarshal(data, &er); err != nil || er.AgentID == "" {
		return nil, errors.New("agent: invalid enrollment response")
	}
	caBlock, _ := pem.Decode([]byte(er.CA))
	if caBlock == nil {
		return nil, errors.New("agent: enrollment response without CA")
	}
	ca, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil || certFP(ca) != normFP(o.CAFingerprint) {
		return nil, errors.New("agent: CA in the response does not match the pinned fingerprint")
	}
	crtBlock, _ := pem.Decode([]byte(er.Certificate))
	if crtBlock == nil {
		return nil, errors.New("agent: enrollment response without certificate")
	}
	crt, err := x509.ParseCertificate(crtBlock.Bytes)
	if err != nil || crt.Subject.CommonName != er.AgentID {
		return nil, errors.New("agent: client certificate does not match the agent id")
	}

	// a new identity starts its own message sequence and a fresh baseline
	for _, f := range []string{p.SigningKey(), p.Seq(), p.Last()} {
		_ = os.Remove(f)
	}
	_ = os.RemoveAll(p.Outbox())
	if err := identity.SaveKey(p.SigningKey(), signKey); err != nil {
		return nil, err
	}
	tlsDER, err := x509.MarshalPKCS8PrivateKey(tlsKey)
	if err != nil {
		return nil, err
	}
	if err := fsutil.WriteFileAtomic(p.TLSKey(), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: tlsDER}), 0o600); err != nil {
		return nil, err
	}
	if err := fsutil.WriteFileAtomic(p.TLSCert(), []byte(er.Certificate), 0o644); err != nil {
		return nil, err
	}
	if err := fsutil.WriteFileAtomic(p.CACert(), []byte(er.CA), 0o644); err != nil {
		return nil, err
	}
	st := &State{Concentrator: u.String(), AgentID: er.AgentID, Status: er.Status, CAFingerprint: normFP(o.CAFingerprint), EnrolledAt: time.Now().UTC()}
	return st, fsutil.WriteJSON(p.State(), st, 0o600)
}

// mtlsClient builds the client used after enrollment: the zone CA as the only root and
// the agent certificate for client authentication.
func mtlsClient(p Paths, serverName string) (*http.Client, error) {
	cert, err := tls.LoadX509KeyPair(p.TLSCert(), p.TLSKey())
	if err != nil {
		return nil, err
	}
	caPEM, err := os.ReadFile(p.CACert())
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("agent: invalid ca.crt")
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, Certificates: []tls.Certificate{cert}, ServerName: serverName}, ForceAttemptHTTP2: true}
	return &http.Client{Timeout: 2 * time.Minute, Transport: tr}, nil
}
