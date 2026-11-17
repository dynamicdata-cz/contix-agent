package concentrator

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/dynamicdata-cz/contix-agent/internal/identity"
	"github.com/dynamicdata-cz/contix-agent/internal/spool"
)

// Defaults for the queue and the forwarder.
const (
	DefaultListen   = ":8443"
	queueMaxBytes   = 2 << 30 // 2 GB
	queueMaxAge     = 7 * 24 * time.Hour
	forwardMaxMsgs  = 1000
	forwardMaxBytes = 7 << 20
	helloEvery      = 15 * time.Minute
)

// RegisterOptions are the inputs of `contix-agent concentrator register`.
type RegisterOptions struct {
	URL     string
	Code    string
	CAFile  string
	Listen  string
	Version string
	Force   bool
	// ServerNames are extra names / IPs for the agent-facing certificate.
	ServerNames []string
}

// Register creates the concentrator key, exchanges the one-time code at CONTIX and writes state.json.
func Register(ctx context.Context, p Paths, o RegisterOptions) (*State, error) {
	if _, err := os.Stat(p.State()); err == nil && !o.Force {
		return nil, fmt.Errorf("concentrator: already registered (%s); use --force to register again", p.State())
	}
	if err := os.MkdirAll(p.Dir, 0o700); err != nil {
		return nil, err
	}
	httpc, err := NewHTTPClient(o.CAFile)
	if err != nil {
		return nil, err
	}
	key, err := identity.GenerateSigningKey()
	if err != nil {
		return nil, err
	}
	host, _ := os.Hostname()
	c := &Client{BaseURL: strings.TrimRight(o.URL, "/"), HTTP: httpc}
	r, err := c.Register(ctx, o.Code, host, o.Version, key.Public().(ed25519.PublicKey))
	if err != nil {
		return nil, err
	}
	if o.Force {
		_ = os.Remove(p.SigningKey())
	}
	if err := identity.SaveKey(p.SigningKey(), key); err != nil {
		return nil, err
	}
	listen := o.Listen
	if listen == "" {
		listen = DefaultListen
	}
	st := &State{URL: c.BaseURL, ConcentratorID: r.ConcentratorID, Zone: r.Zone, CAFile: o.CAFile, Listen: listen, ServerNames: o.ServerNames}
	if err := writeJSON(p.State(), st, 0o600); err != nil {
		return nil, err
	}
	if _, _, err := EnsureCA(p, st.Zone, st.ConcentratorID); err != nil {
		return nil, err
	}
	return st, nil
}

// hostNames returns the hostname, configured extra names and non-loopback IP addresses for the server certificate.
func hostNames(extra []string) []string {
	h, _ := os.Hostname()
	out := []string{h}
	for _, n := range extra {
		if n = strings.TrimSpace(n); n != "" && !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		slog.Warn("cannot list interface addresses – the server certificate will contain only names", "err", err)
	}
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && !ipn.IP.IsLoopback() && !ipn.IP.IsLinkLocalUnicast() {
			out = append(out, ipn.IP.String())
		}
	}
	return out
}

// Runner keeps forwarder state for status reports.
type Runner struct {
	mu          sync.Mutex
	lastForward time.Time
	lastErr     string
}

func (r *Runner) note(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err != nil {
		r.lastErr = err.Error()
		return
	}
	r.lastForward, r.lastErr = time.Now(), ""
}

// ForwardOnce sends the oldest queued messages to CONTIX. It returns how many messages were
// forwarded; files are deleted only after CONTIX answered 2xx (stored or duplicate).
func ForwardOnce(ctx context.Context, q *spool.Queue, c *Client, log *slog.Logger) (int, error) {
	names, msgs, err := q.Next(forwardMaxMsgs, forwardMaxBytes)
	if err != nil || len(names) == 0 {
		return 0, err
	}
	res, err := c.SendBatch(ctx, msgs)
	var he *HTTPError
	if errors.As(err, &he) && he.Permanent() {
		log.Error("CONTIX refused batch permanently, moving to dead/", "files", len(names), "err", err)
		return 0, q.Dead(names)
	}
	if err != nil {
		return 0, err
	}
	if len(res.Rejected) > 0 {
		log.Warn("CONTIX rejected messages", "rejected", len(res.Rejected), "first", res.Rejected[0].Reason)
	}
	return len(msgs), q.Done(names)
}

// Run serves agents and forwards to CONTIX until ctx is cancelled.
func Run(ctx context.Context, p Paths, version string, log *slog.Logger) error {
	st, key, err := LoadState(p)
	if err != nil {
		return err
	}
	httpc, err := NewHTTPClient(st.CAFile)
	if err != nil {
		return err
	}
	client := &Client{BaseURL: st.URL, ID: st.ConcentratorID, Key: key, HTTP: httpc}
	ca, caKey, err := EnsureCA(p, st.Zone, st.ConcentratorID)
	if err != nil {
		return err
	}
	if err := EnsureServerCert(p, ca, caKey, hostNames(st.ServerNames)); err != nil {
		return err
	}
	tlsCfg, err := TLSConfig(p, ca)
	if err != nil {
		return err
	}
	reg, err := LoadRegistry(p)
	if err != nil {
		return err
	}
	q, err := spool.NewQueue(p.Queue(), queueMaxBytes, queueMaxAge)
	if err != nil {
		return err
	}
	srv := &Server{Registry: reg, Queue: q, Upstream: client, CA: ca, CAKey: caKey, Log: log}
	listen := st.Listen
	if listen == "" {
		listen = DefaultListen
	}
	hs := &http.Server{Addr: listen, Handler: srv.Handler(), TLSConfig: tlsCfg, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 60 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 120 * time.Second}
	errc := make(chan error, 1)
	go func() {
		log.Info("concentrator listening", "addr", listen, "zone", st.Zone, "contix", st.URL, "caFingerprint", CAFingerprint(ca))
		if err := hs.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errc <- err
		}
	}()

	runner := &Runner{}
	start := time.Now()
	host, _ := os.Hostname()
	hello := func() error {
		files, bytes := q.Stats()
		runner.mu.Lock()
		s := Status{Version: version, Hostname: host, UptimeSeconds: int64(time.Since(start).Seconds()), Agents: reg.Agents(), QueueFiles: files, QueueBytes: bytes, LastError: runner.lastErr, CACertExpires: ca.NotAfter.UTC().Format(time.RFC3339)}
		if !runner.lastForward.IsZero() {
			s.LastForwardAt = runner.lastForward.UTC().Format(time.RFC3339)
		}
		runner.mu.Unlock()
		hctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		err := client.Hello(hctx, s)
		if err != nil {
			log.Warn("hello to CONTIX failed", "err", err)
		}
		return err
	}
	// first hello; retried every minute until CONTIX answers, then every 15 minutes
	helloRetry := time.NewTimer(time.Hour)
	helloRetry.Stop()
	defer helloRetry.Stop()
	if hello() != nil {
		helloRetry.Reset(time.Minute)
	}

	backoff := 5 * time.Second
	fwd := time.NewTimer(time.Second)
	helloT := time.NewTicker(helloEvery)
	pruneT := time.NewTicker(time.Hour)
	defer fwd.Stop()
	defer helloT.Stop()
	defer pruneT.Stop()
	for {
		select {
		case <-ctx.Done():
			sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			return hs.Shutdown(sctx)
		case err := <-errc:
			return err
		case <-helloT.C:
			_ = hello()
		case <-helloRetry.C:
			if hello() != nil {
				helloRetry.Reset(time.Minute)
			}
		case <-pruneT.C:
			if n, _ := q.Prune(time.Now()); n > 0 {
				log.Warn("queue files older than retention deleted", "files", n)
			}
		case <-fwd.C:
			fctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
			n, err := ForwardOnce(fctx, q, client, log)
			cancel()
			if err != nil || n > 0 {
				runner.note(err)
			}
			switch {
			case err != nil:
				log.Warn("forward to CONTIX failed, will retry", "err", err, "retryIn", backoff)
				fwd.Reset(backoff)
				backoff = min(backoff*2, 5*time.Minute)
			case n > 0:
				backoff = 5 * time.Second
				fwd.Reset(0) // more may be waiting
			default:
				backoff = 5 * time.Second
				fwd.Reset(5 * time.Second)
			}
		}
	}
}
