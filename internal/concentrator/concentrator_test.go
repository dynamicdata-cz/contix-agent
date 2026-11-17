package concentrator

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dynamicdata-cz/contix-agent/internal/identity"
	"github.com/dynamicdata-cz/contix-agent/internal/protocol"
	"github.com/dynamicdata-cz/contix-agent/internal/spool"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

// fakeContix verifies concentrator signatures exactly like CONTIX and records what it received.
type fakeContix struct {
	t        *testing.T
	pub      ed25519.PublicKey
	mu       sync.Mutex
	messages []json.RawMessage
	hellos   int
	status   int // forced status for /batches (0 = 200)
	agents   map[string]string
}

func (f *fakeContix) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.HasSuffix(r.URL.Path, "/register") {
			var in struct{ Code, PublicKey string }
			_ = json.Unmarshal(body, &in)
			if in.Code != "ctxr_ok" {
				w.WriteHeader(401)
				return
			}
			k, _ := base64.StdEncoding.DecodeString(in.PublicKey)
			f.pub = k
			w.WriteHeader(201)
			_, _ = w.Write([]byte(`{"concentratorId":"11111111-2222-4333-8444-555555555555","zone":"kancelar"}`))
			return
		}
		date := r.Header.Get(headerDate)
		sig, _ := base64.StdEncoding.DecodeString(r.Header.Get(headerSignature))
		if r.Header.Get(headerID) != "11111111-2222-4333-8444-555555555555" || !ed25519.Verify(f.pub, []byte(SigningString(r.Method, r.URL.Path, date, body)), sig) {
			w.WriteHeader(401)
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		switch {
		case strings.HasSuffix(r.URL.Path, "/agents"):
			var a AgentInfo
			_ = json.Unmarshal(body, &a)
			id := "aaaaaaaa-0000-4000-8000-" + strings.Repeat("0", 12-len(a.HostID)) + a.HostID
			if f.agents == nil {
				f.agents = map[string]string{}
			}
			f.agents[id] = a.PublicKey
			_ = json.NewEncoder(w).Encode(AgentRegistration{AgentID: id, Status: "pending"})
		case strings.HasSuffix(r.URL.Path, "/batches"):
			if f.status != 0 {
				w.WriteHeader(f.status)
				return
			}
			var in struct{ Messages []json.RawMessage }
			_ = json.Unmarshal(body, &in)
			f.messages = append(f.messages, in.Messages...)
			_, _ = w.Write([]byte(`{"acks":{},"accepted":1,"duplicates":0,"rejected":[]}`))
		case strings.HasSuffix(r.URL.Path, "/hello"):
			f.hellos++
			_, _ = w.Write([]byte(`{"ok":true}`))
		default:
			w.WriteHeader(404)
		}
	})
}

type agentSim struct {
	signKey ed25519.PrivateKey
	tlsKey  *ecdsa.PrivateKey
	id      string
	cert    tls.Certificate
}

func newAgentSim(t *testing.T) *agentSim {
	sk, _ := identity.GenerateSigningKey()
	tk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return &agentSim{signKey: sk, tlsKey: tk}
}

func (a *agentSim) csr(t *testing.T) string {
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "agent"}}, a.tlsKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func (a *agentSim) msg(t *testing.T, seq uint64, agent string) json.RawMessage {
	e := protocol.Envelope{V: 1, Agent: agent, Seq: seq, TS: time.Now().UTC().Truncate(time.Second), Kind: protocol.KindHello, Payload: json.RawMessage(`{"version":"0.1.0"}`)}
	if err := e.Sign(a.signKey); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(e)
	return b
}

func setup(t *testing.T) (Paths, *fakeContix, *httptest.Server, *Client) {
	t.Helper()
	fc := &fakeContix{t: t}
	contix := httptest.NewTLSServer(fc.handler())
	t.Cleanup(contix.Close)
	caFile := filepath.Join(t.TempDir(), "contix-ca.crt")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: contix.Certificate().Raw}), 0o644); err != nil {
		t.Fatal(err)
	}
	p := Paths{Dir: filepath.Join(t.TempDir(), "state")}
	if _, err := Register(context.Background(), p, RegisterOptions{URL: contix.URL, Code: "ctxr_bad", CAFile: caFile}); err == nil {
		t.Fatal("bad code accepted")
	}
	st, err := Register(context.Background(), p, RegisterOptions{URL: contix.URL, Code: "ctxr_ok", CAFile: caFile, Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Register(context.Background(), p, RegisterOptions{URL: contix.URL, Code: "ctxr_ok", CAFile: caFile}); err == nil {
		t.Fatal("second registration without --force must fail")
	}
	if st.Zone != "kancelar" {
		t.Fatalf("zone %q", st.Zone)
	}
	if info, _ := os.Stat(p.SigningKey()); info.Mode().Perm() != 0o600 {
		t.Fatalf("signing key mode %v", info.Mode().Perm())
	}
	if info, _ := os.Stat(p.CAKey()); info.Mode().Perm() != 0o600 {
		t.Fatalf("CA key mode %v", info.Mode().Perm())
	}
	st2, key, err := LoadState(p)
	if err != nil {
		t.Fatal(err)
	}
	httpc, _ := NewHTTPClient(st2.CAFile)
	return p, fc, contix, &Client{BaseURL: st2.URL, ID: st2.ConcentratorID, Key: key, HTTP: httpc}
}

func TestEndToEnd(t *testing.T) {
	p, fc, _, client := setup(t)
	ca, caKey, err := EnsureCA(p, "kancelar", "x")
	if err != nil {
		t.Fatal(err)
	}
	if err := EnsureServerCert(p, ca, caKey, []string{"127.0.0.1", "localhost"}); err != nil {
		t.Fatal(err)
	}
	tlsCfg, err := TLSConfig(p, ca)
	if err != nil {
		t.Fatal(err)
	}
	reg, _ := LoadRegistry(p)
	q, _ := spool.NewQueue(p.Queue(), 1<<20, time.Hour)
	srv := &Server{Registry: reg, Queue: q, Upstream: client, CA: ca, CAKey: caKey, Log: quiet}
	hs := httptest.NewUnstartedServer(srv.Handler())
	hs.TLS = tlsCfg
	hs.StartTLS()
	defer hs.Close()

	pool := x509.NewCertPool()
	pool.AddCert(ca)
	plain := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	post := (func(c *http.Client, path string, body any) (*http.Response, []byte))(func(c *http.Client, path string, body any) (*http.Response, []byte) {
		b, _ := json.Marshal(body)
		resp, err := c.Post(hs.URL+path, "application/json", bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(resp.Body)
		return resp, data
	})

	// enrollment: token is required, single use
	a := newAgentSim(t)
	enroll := AgentEnrollRequest{HostID: "42", Hostname: "srv-app-01", OS: "Ubuntu", Version: "0.1.0", PublicKey: base64.StdEncoding.EncodeToString(a.signKey.Public().(ed25519.PublicKey)), CSR: a.csr(t)}
	if r, _ := post(plain, "/v1/enroll", enroll); r.StatusCode != 401 {
		t.Fatalf("enroll without token: %d", r.StatusCode)
	}
	tok, _ := reg.CreateToken(1, time.Hour)
	enroll.Token = tok
	r, body := post(plain, "/v1/enroll", enroll)
	if r.StatusCode != 200 {
		t.Fatalf("enroll: %d %s", r.StatusCode, body)
	}
	var er AgentEnrollResponse
	_ = json.Unmarshal(body, &er)
	if er.Status != "pending" || !strings.HasPrefix(er.AgentID, "aaaaaaaa-") {
		t.Fatalf("enroll response %+v", er)
	}
	if r, _ := post(plain, "/v1/enroll", enroll); r.StatusCode != 401 {
		t.Fatalf("token reuse: %d", r.StatusCode)
	}
	block, _ := pem.Decode([]byte(er.Certificate))
	a.cert = tls.Certificate{Certificate: [][]byte{block.Bytes}, PrivateKey: a.tlsKey}
	a.id = er.AgentID
	mtls := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, Certificates: []tls.Certificate{a.cert}}}}

	// batch: client certificate required; signatures checked already in the concentrator
	if r, _ := post(plain, "/v1/batch", map[string]any{"messages": []json.RawMessage{a.msg(t, 1, a.id)}}); r.StatusCode != 401 {
		t.Fatalf("batch without client cert: %d", r.StatusCode)
	}
	other := newAgentSim(t)
	forged := other.msg(t, 3, a.id)                                // signed by a different key
	foreign := a.msg(t, 4, "bbbbbbbb-0000-4000-8000-000000000001") // not this agent's id
	r, body = post(mtls, "/v1/batch", map[string]any{"messages": []json.RawMessage{a.msg(t, 1, a.id), a.msg(t, 2, a.id), forged, foreign}})
	if r.StatusCode != 200 {
		t.Fatalf("batch: %d %s", r.StatusCode, body)
	}
	var br struct {
		Queued   int
		Rejected []struct{ Index int }
	}
	_ = json.Unmarshal(body, &br)
	if br.Queued != 2 || len(br.Rejected) != 2 {
		t.Fatalf("batch result %s", body)
	}
	if files, _ := q.Stats(); files != 1 {
		t.Fatalf("queue files %d", files)
	}

	// forward: signed request to CONTIX, queue emptied only on success, messages unchanged
	n, err := ForwardOnce(context.Background(), q, client, quiet)
	if err != nil || n != 2 {
		t.Fatalf("forward: %d %v", n, err)
	}
	if files, _ := q.Stats(); files != 0 {
		t.Fatal("queue not emptied")
	}
	pub := a.signKey.Public().(ed25519.PublicKey)
	for _, m := range fc.messages {
		if _, err := protocol.VerifyRaw(m, pub); err != nil {
			t.Fatalf("forwarded message no longer verifies: %v", err)
		}
	}
	// CONTIX down: data stays queued; malformed batch: moved aside
	_, _ = post(mtls, "/v1/batch", map[string]any{"messages": []json.RawMessage{a.msg(t, 5, a.id)}})
	fc.status = 503
	if _, err := ForwardOnce(context.Background(), q, client, quiet); err == nil {
		t.Fatal("expected error when CONTIX is down")
	}
	if files, _ := q.Stats(); files != 1 {
		t.Fatal("queued data lost on CONTIX error")
	}
	fc.status = 400
	if _, err := ForwardOnce(context.Background(), q, client, quiet); err != nil {
		t.Fatal(err)
	}
	if files, _ := q.Stats(); files != 0 {
		t.Fatal("permanently refused batch not moved to dead/")
	}
	if dead, _ := os.ReadDir(filepath.Join(p.Queue(), "dead")); len(dead) != 1 {
		t.Fatalf("dead files %d", len(dead))
	}
	if err := client.Hello(context.Background(), Status{Version: "test"}); err != nil || fc.hellos != 1 {
		t.Fatalf("hello: %v %d", err, fc.hellos)
	}
}

func TestQueueFullAndPrune(t *testing.T) {
	q, _ := spool.NewQueue(t.TempDir(), 100, time.Hour)
	if err := q.Append([]json.RawMessage{json.RawMessage(`{"a":"` + strings.Repeat("x", 80) + `"}`)}); err != nil {
		t.Fatal(err)
	}
	if err := q.Append([]json.RawMessage{json.RawMessage(`{"b":"` + strings.Repeat("y", 80) + `"}`)}); !errors.Is(err, spool.ErrQueueFull) {
		t.Fatalf("err %v, want spool.ErrQueueFull", err)
	}
	if n, _ := q.Prune(time.Now().Add(2 * time.Hour)); n != 1 {
		t.Fatalf("pruned %d", n)
	}
}

func TestSigningStringMatchesContix(t *testing.T) {
	// same inputs and expected text as concentratorSigningString in CONTIX (packages/shared/src/agentProtocol.ts)
	got := SigningString("post", "/api/public/agent/v1/batches", "2026-11-17T08:12:44Z", []byte(`{"messages":[]}`))
	want := "CONTIX-CONCENTRATOR-V1\nPOST\n/api/public/agent/v1/batches\n2026-11-17T08:12:44Z\n5e4ce7b36ba37b78a5d5f9fd08e6b7b54ba6879d651aa46ec9e1d6fa24ebe30a"
	if got != want {
		t.Fatalf("signing string\n got  %q\n want %q", got, want)
	}
}

func TestServerCertRenewOnHostChange(t *testing.T) {
	p := Paths{Dir: t.TempDir()}
	ca, key, _ := EnsureCA(p, "z", "id")
	if err := EnsureServerCert(p, ca, key, []string{"host-a", "192.0.2.10"}); err != nil {
		t.Fatal(err)
	}
	c1, _ := readCert(p.ServerCert())
	_ = EnsureServerCert(p, ca, key, []string{"192.0.2.10", "host-a"})
	c2, _ := readCert(p.ServerCert())
	if c1.SerialNumber.Cmp(c2.SerialNumber) != 0 {
		t.Fatal("certificate reissued although hosts did not change")
	}
	_ = EnsureServerCert(p, ca, key, []string{"host-b"})
	c3, _ := readCert(p.ServerCert())
	if c3.SerialNumber.Cmp(c1.SerialNumber) == 0 || c3.DNSNames[0] != "host-b" {
		t.Fatal("certificate not reissued for new host")
	}
	if _, err := c3.Verify(x509.VerifyOptions{Roots: func() *x509.CertPool { p := x509.NewCertPool(); p.AddCert(ca); return p }(), DNSName: "host-b"}); err != nil {
		t.Fatal(err)
	}
}

func TestReenrollReplacesHost(t *testing.T) {
	p := Paths{Dir: t.TempDir()}
	r, _ := LoadRegistry(p)
	_ = r.PutAgent("old-id", AgentRecord{PublicKey: base64.StdEncoding.EncodeToString(make([]byte, 32)), HostID: "h1"})
	_ = r.PutAgent("other", AgentRecord{PublicKey: base64.StdEncoding.EncodeToString(make([]byte, 32)), HostID: "h2"})
	_ = r.PutAgent("new-id", AgentRecord{PublicKey: base64.StdEncoding.EncodeToString(make([]byte, 32)), HostID: "h1"})
	if _, ok := r.AgentKey("old-id"); ok {
		t.Fatal("old identity of the host still accepted")
	}
	if r.Agents() != 2 {
		t.Fatalf("agents %d", r.Agents())
	}
	r2, _ := LoadRegistry(p)
	if _, ok := r2.AgentKey("new-id"); !ok || r2.Agents() != 2 {
		t.Fatal("registry not persisted")
	}
}
