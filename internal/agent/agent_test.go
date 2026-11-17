package agent

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dynamicdata-cz/contix-agent/internal/concentrator"
	"github.com/dynamicdata-cz/contix-agent/internal/protocol"
	"github.com/dynamicdata-cz/contix-agent/internal/spool"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

type fakeUpstream struct{ keys map[string]string }

func (f *fakeUpstream) RegisterAgent(_ context.Context, a concentrator.AgentInfo) (*concentrator.AgentRegistration, error) {
	id := "aaaaaaaa-0000-4000-8000-000000000001"
	f.keys[id] = a.PublicKey
	return &concentrator.AgentRegistration{AgentID: id, Status: "pending"}, nil
}

// startConcentrator runs a real concentrator server (zone CA, chain, mTLS) on 127.0.0.1.
func startConcentrator(t *testing.T, hosts ...string) (*httptest.Server, *concentrator.Registry, *spool.Queue, string, *fakeUpstream) {
	t.Helper()
	cp := concentrator.Paths{Dir: t.TempDir()}
	ca, caKey, err := concentrator.EnsureCA(cp, "kancelar", "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) == 0 {
		hosts = []string{"127.0.0.1"}
	}
	if err := concentrator.EnsureServerCert(cp, ca, caKey, hosts); err != nil {
		t.Fatal(err)
	}
	tlsCfg, err := concentrator.TLSConfig(cp, ca)
	if err != nil {
		t.Fatal(err)
	}
	reg, _ := concentrator.LoadRegistry(cp)
	q, _ := spool.NewQueue(filepath.Join(cp.Dir, "queue"), 1<<24, time.Hour)
	up := &fakeUpstream{keys: map[string]string{}}
	srv := &concentrator.Server{Registry: reg, Queue: q, Upstream: up, CA: ca, CAKey: caKey, Log: quiet}
	hs := httptest.NewUnstartedServer(srv.Handler())
	hs.TLS = tlsCfg
	hs.StartTLS()
	t.Cleanup(hs.Close)
	return hs, reg, q, concentrator.CAFingerprint(ca), up
}

func fixtureCollector(t *testing.T) (*Collector, string) {
	root := t.TempDir()
	writeFiles(t, root, map[string]string{
		"/proc/sys/kernel/hostname": "srv-app-01\n",
		"/etc/machine-id":           "0f1e2d3c4b5a69788796a5b4c3d2e1f0\n",
		"/etc/os-release":           "PRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\n",
		"/proc/net/tcp":             "  sl  local_address rem_address   st\n   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1111 1 0\n",
		"/etc/passwd":               "root:x:0:0:root:/root:/bin/bash\n",
		"/var/lib/dpkg/status":      "Package: openssh-server\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1:9.6p1\n",
	})
	return &Collector{Root: root}, root
}

func TestEnrollPinningAndSend(t *testing.T) {
	hs, reg, q, fp, up := startConcentrator(t)
	coll, root := fixtureCollector(t)
	p := Paths{Dir: filepath.Join(t.TempDir(), "agent")}
	tok, _ := reg.CreateToken(2, time.Hour)

	// a concentrator with a different CA (or a MITM) is refused before the token is sent
	wrong := strings.Repeat("ab", 32)
	if _, err := Enroll(context.Background(), p, coll, EnrollOptions{Concentrator: hs.URL, Token: tok, CAFingerprint: wrong}); err == nil || !strings.Contains(err.Error(), "pinned") {
		t.Fatalf("wrong fingerprint accepted: %v", err)
	}
	if err := reg.CheckToken(tok, time.Now()); err != nil {
		t.Fatal("token consumed by a refused connection")
	}
	if _, err := Enroll(context.Background(), p, coll, EnrollOptions{Concentrator: "http://127.0.0.1:1", Token: tok, CAFingerprint: fp}); err == nil {
		t.Fatal("plain http accepted")
	}
	st, err := Enroll(context.Background(), p, coll, EnrollOptions{Concentrator: hs.URL, Token: tok, CAFingerprint: strings.ToUpper(fp), Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if st.AgentID != "aaaaaaaa-0000-4000-8000-000000000001" || st.Status != "pending" {
		t.Fatalf("state %+v", st)
	}
	for _, f := range []string{p.SigningKey(), p.TLSKey(), p.State()} {
		if info, _ := os.Stat(f); info.Mode().Perm() != 0o600 {
			t.Errorf("%s mode %v", f, info.Mode().Perm())
		}
	}
	if _, err := Enroll(context.Background(), p, coll, EnrollOptions{Concentrator: hs.URL, Token: tok, CAFingerprint: fp}); err == nil {
		t.Fatal("second enrollment without --force")
	}

	a, err := Open(p, coll, "test", quiet)
	if err != nil {
		t.Fatal(err)
	}
	hc, err := mtlsClient(p, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if n, err := a.CollectAndEmit(context.Background(), false); err != nil || n != -1 {
		t.Fatalf("first collect must be a snapshot: %d %v", n, err)
	}
	if n, err := a.CollectAndEmit(context.Background(), false); err != nil || n != 0 {
		t.Fatalf("no change expected: %d %v", n, err)
	}
	// a new listening port appears
	writeFiles(t, root, map[string]string{"/proc/net/tcp": "  sl  local_address rem_address   st\n   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1111 1 0\n   1: 00000000:0017 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2222 1 0\n"})
	if n, err := a.CollectAndEmit(context.Background(), false); err != nil || n != 1 {
		t.Fatalf("one change expected: %d %v", n, err)
	}
	if n, err := a.SendOnce(context.Background(), hc); err != nil || n != 2 {
		t.Fatalf("send: %d %v", n, err)
	}
	if files, _ := a.outbox.Stats(); files != 0 {
		t.Fatal("outbox not emptied")
	}
	// the concentrator queued both messages, verifiable with the agent key from enrollment
	_, msgs, _ := q.Next(10, 1<<20)
	if len(msgs) != 2 {
		t.Fatalf("concentrator queue %d", len(msgs))
	}
	pub, _ := base64.StdEncoding.DecodeString(up.keys[st.AgentID])
	var kinds []string
	for _, m := range msgs {
		e, err := protocol.VerifyRaw(m, ed25519.PublicKey(pub))
		if err != nil {
			t.Fatal(err)
		}
		kinds = append(kinds, string(e.Kind)+":"+string(rune('0'+e.Seq)))
		if e.Kind == protocol.KindChange && !strings.Contains(string(e.Payload), `"tcp/0.0.0.0:23"`) {
			t.Fatalf("change payload %s", e.Payload)
		}
	}
	if strings.Join(kinds, ",") != "snapshot:1,change:2" {
		t.Fatalf("messages %v", kinds)
	}
	// sequence continues after restart
	a2, _ := Open(p, coll, "test", quiet)
	if a2.seq != 2 || a2.last == nil {
		t.Fatalf("restart: seq %d last %v", a2.seq, a2.last != nil)
	}
	if err := a2.hello(a2.coll.Collect(context.Background(), nil)); err != nil {
		t.Fatal(err)
	}
	if _, err := a2.SendOnce(context.Background(), hc); err != nil {
		t.Fatal(err)
	}
	_, msgs, _ = q.Next(10, 1<<20)
	var last protocol.Envelope
	_ = json.Unmarshal(msgs[len(msgs)-1], &last)
	if last.Seq != 3 || last.Kind != protocol.KindHello {
		t.Fatalf("hello after restart: %+v", last)
	}
	if out, err := Status(p); err != nil || !strings.Contains(out, st.AgentID) {
		t.Fatalf("status: %v %s", err, out)
	}
}

func TestSendRejectedWithoutValidCertificate(t *testing.T) {
	hs, reg, _, fp, _ := startConcentrator(t)
	coll, _ := fixtureCollector(t)
	p := Paths{Dir: t.TempDir()}
	tok, _ := reg.CreateToken(1, time.Hour)
	if _, err := Enroll(context.Background(), p, coll, EnrollOptions{Concentrator: hs.URL, Token: tok, CAFingerprint: fp}); err != nil {
		t.Fatal(err)
	}
	// another concentrator (different zone CA) must not accept this agent's certificate
	hs2, _, _, _, _ := startConcentrator(t)
	a, _ := Open(p, coll, "test", quiet)
	a.st.Concentrator = hs2.URL
	_, _ = a.CollectAndEmit(context.Background(), true)
	hc, _ := mtlsClient(p, "127.0.0.1")
	if _, err := a.SendOnce(context.Background(), hc); err == nil {
		t.Fatal("agent sent to a concentrator of another zone")
	}
	if files, _ := a.outbox.Stats(); files != 1 {
		t.Fatal("message lost after a failed send")
	}
}

func TestEnrollRefusesCertificateWithoutConnectedIP(t *testing.T) {
	// as on a server whose certificate got only its host name: connecting by IP must fail at enrollment,
	// not later when sending (pinned CA alone is not enough – the name must match too)
	hs, reg, _, fp, _ := startConcentrator(t, "ctx-konc-example")
	coll, _ := fixtureCollector(t)
	tok, _ := reg.CreateToken(1, time.Hour)
	_, err := Enroll(context.Background(), Paths{Dir: t.TempDir()}, coll, EnrollOptions{Concentrator: hs.URL, Token: tok, CAFingerprint: fp})
	if err == nil || !strings.Contains(err.Error(), "IP SANs") {
		t.Fatalf("enrollment by IP accepted a certificate without that IP: %v", err)
	}
}
