package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dynamicdata-cz/contix-agent/internal/fsutil"
	"github.com/dynamicdata-cz/contix-agent/internal/identity"
	"github.com/dynamicdata-cz/contix-agent/internal/protocol"
	"github.com/dynamicdata-cz/contix-agent/internal/spool"
)

// Schedule of the agent (ADR-177): hello every 15 min, change check every 5 min, full snapshot daily.
const (
	helloEvery     = 15 * time.Minute
	checkEvery     = 5 * time.Minute
	snapshotEvery  = 24 * time.Hour
	outboxMaxBytes = 256 << 20
	outboxMaxAge   = 7 * 24 * time.Hour
	sendMaxMsgs    = 500
	sendMaxBytes   = 7 << 20
)

// Agent emits signed messages into its outbox and sends them to the concentrator.
type Agent struct {
	p       Paths
	st      *State
	key     ed25519.PrivateKey
	outbox  *spool.Queue
	coll    *Collector
	modules []string
	version string
	log     *slog.Logger

	mu   sync.Mutex
	seq  uint64
	last *Snapshot
}

// Open loads an enrolled agent.
func Open(p Paths, c *Collector, version string, log *slog.Logger) (*Agent, error) {
	st, err := LoadState(p)
	if err != nil {
		return nil, err
	}
	key, err := identity.LoadKey(p.SigningKey())
	if err != nil {
		return nil, err
	}
	q, err := spool.NewQueue(p.Outbox(), outboxMaxBytes, outboxMaxAge)
	if err != nil {
		return nil, err
	}
	a := &Agent{p: p, st: st, key: key, outbox: q, coll: c, modules: AllModules, version: version, log: log}
	if b, err := os.ReadFile(p.Seq()); err == nil {
		a.seq, _ = strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	}
	var last Snapshot
	if err := fsutil.ReadJSON(p.Last(), &last); err == nil && last.Modules != nil {
		a.last = &last
	}
	return a, nil
}

// emit signs a message with the next sequence number and stores it in the outbox.
// The sequence number is persisted before the message exists, so it is never reused.
func (a *Agent) emit(kind protocol.Kind, payload any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	next := a.seq + 1
	if err := fsutil.WriteFileAtomic(a.p.Seq(), []byte(strconv.FormatUint(next, 10)+"\n"), 0o600); err != nil {
		return err
	}
	a.seq = next
	e := protocol.Envelope{V: protocol.Version, Agent: a.st.AgentID, Seq: next, TS: time.Now().UTC(), Kind: kind, Payload: raw}
	if err := e.Sign(a.key); err != nil {
		return err
	}
	msg, err := json.Marshal(e)
	if err != nil {
		return err
	}
	return a.outbox.Append([]json.RawMessage{msg})
}

func (a *Agent) hello(s *Snapshot) error {
	mods := map[string]string{}
	for _, m := range a.modules {
		mods[m] = "ok"
	}
	for m, e := range s.Errors {
		mods[m] = "error: " + e
	}
	files, bytes := a.outbox.Stats()
	return a.emit(protocol.KindHello, map[string]any{
		"version": a.version, "hostname": s.Host.Hostname, "os": s.Host.OS, "kernel": s.Host.Kernel,
		"uptimeSeconds": s.Host.Uptime, "modules": mods, "outboxFiles": files, "outboxBytes": bytes,
	})
}

// CollectAndEmit collects the host state and emits a full snapshot (full=true) or the changes
// since the last state. The new state becomes the baseline only after the message is queued.
func (a *Agent) CollectAndEmit(ctx context.Context, full bool) (int, error) {
	s := a.coll.Collect(ctx, a.modules)
	if full || a.last == nil {
		if err := a.emit(protocol.KindSnapshot, s); err != nil {
			return 0, err
		}
	} else {
		changes := Diff(a.last, s)
		if len(changes) == 0 {
			a.last = s
			return 0, a.saveLast()
		}
		if err := a.emit(protocol.KindChange, map[string]any{"detected": time.Now().UTC().Format(time.RFC3339), "changes": changes}); err != nil {
			return 0, err
		}
		a.last = s
		return len(changes), a.saveLast()
	}
	a.last = s
	return -1, a.saveLast()
}

func (a *Agent) saveLast() error { return fsutil.WriteJSON(a.p.Last(), a.last, 0o600) }

// ErrRejected means the concentrator does not accept this agent (blocked / unknown / bad certificate).
var ErrRejected = errors.New("agent: concentrator rejected the agent")

// SendOnce sends the oldest outbox messages; they are removed only after the concentrator stored them.
func (a *Agent) SendOnce(ctx context.Context, hc *http.Client) (int, error) {
	names, msgs, err := a.outbox.Next(sendMaxMsgs, sendMaxBytes)
	if err != nil || len(names) == 0 {
		return 0, err
	}
	body, _ := json.Marshal(map[string]any{"messages": msgs})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.st.Concentrator+"/v1/batch", bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	switch {
	case resp.StatusCode == http.StatusOK:
		var r struct {
			Queued   int `json:"queued"`
			Rejected []struct {
				Index  int    `json:"index"`
				Reason string `json:"reason"`
			} `json:"rejected"`
		}
		_ = json.Unmarshal(data, &r)
		if len(r.Rejected) > 0 {
			a.log.Warn("concentrator rejected messages", "rejected", len(r.Rejected), "first", r.Rejected[0].Reason)
		}
		return len(msgs), a.outbox.Done(names)
	case resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusRequestEntityTooLarge:
		a.log.Error("concentrator refused batch permanently, moving to dead/", "status", resp.StatusCode, "body", strings.TrimSpace(string(data)))
		return 0, a.outbox.Dead(names)
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return 0, fmt.Errorf("%w: HTTP %d: %s", ErrRejected, resp.StatusCode, strings.TrimSpace(string(data)))
	default:
		return 0, fmt.Errorf("agent: concentrator HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
}

// Run collects and sends until ctx is cancelled.
func Run(ctx context.Context, p Paths, version string, log *slog.Logger) error {
	a, err := Open(p, NewCollector(), version, log)
	if err != nil {
		return err
	}
	u, err := url.Parse(a.st.Concentrator)
	if err != nil {
		return err
	}
	hc, err := mtlsClient(p, u.Hostname())
	if err != nil {
		return err
	}
	log.Info("agent started", "agent", a.st.AgentID, "concentrator", a.st.Concentrator, "seq", a.seq)

	first := a.coll.Collect(ctx, a.modules)
	if err := a.hello(first); err != nil {
		log.Error("hello failed", "err", err)
	}
	if _, err := a.CollectAndEmit(ctx, true); err != nil {
		log.Error("snapshot failed", "err", err)
	}

	jitter := time.Duration(rand.Int64N(int64(time.Hour)))
	helloT := time.NewTicker(helloEvery)
	checkT := time.NewTicker(checkEvery)
	snapT := time.NewTimer(snapshotEvery + jitter)
	pruneT := time.NewTicker(time.Hour)
	send := time.NewTimer(time.Second)
	defer helloT.Stop()
	defer checkT.Stop()
	defer snapT.Stop()
	defer pruneT.Stop()
	defer send.Stop()
	backoff := 5 * time.Second
	// delivered = last send succeeded; the first success after start or a failure is logged
	delivered := false
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-helloT.C:
			hs := a.coll.Collect(ctx, nil)
			if a.last != nil {
				hs.Errors = a.last.Errors
			}
			if err := a.hello(hs); err != nil {
				log.Error("hello failed", "err", err)
			}
		case <-checkT.C:
			n, err := a.CollectAndEmit(ctx, false)
			if err != nil {
				log.Error("change check failed", "err", err)
			} else if n > 0 {
				log.Info("changes detected", "count", n)
			}
		case <-snapT.C:
			if _, err := a.CollectAndEmit(ctx, true); err != nil {
				log.Error("snapshot failed", "err", err)
			}
			snapT.Reset(snapshotEvery)
		case <-pruneT.C:
			if n, _ := a.outbox.Prune(time.Now()); n > 0 {
				log.Warn("outbox messages older than retention deleted", "files", n)
			}
		case <-send.C:
			sctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
			n, err := a.SendOnce(sctx, hc)
			cancel()
			switch {
			case errors.Is(err, ErrRejected):
				log.Error("concentrator rejects this agent – check approval in CONTIX or enroll again", "err", err)
				delivered = false
				send.Reset(5 * time.Minute)
			case err != nil:
				delivered = false
				log.Warn("send to concentrator failed, will retry", "err", err, "retryIn", backoff)
				send.Reset(backoff)
				backoff = min(backoff*2, 5*time.Minute)
			case n > 0:
				if !delivered {
					files, _ := a.outbox.Stats()
					log.Info("messages delivered to concentrator", "count", n, "outbox", files)
					delivered = true
				}
				backoff = 5 * time.Second
				send.Reset(0)
			default:
				backoff = 5 * time.Second
				send.Reset(10 * time.Second)
			}
		}
	}
}

// Status is a local summary for `agent status`.
func Status(p Paths) (string, error) {
	st, err := LoadState(p)
	if err != nil {
		return "", err
	}
	q, err := spool.NewQueue(p.Outbox(), 1, time.Hour)
	if err != nil {
		return "", err
	}
	files, size := q.Stats()
	seq, _ := os.ReadFile(p.Seq())
	lastAt := "-"
	if info, err := os.Stat(p.Last()); err == nil {
		lastAt = info.ModTime().Format(time.RFC3339)
	}
	return fmt.Sprintf("agent        %s\nstatus       %s (at enrollment)\nconcentrator %s\nzone CA      %s\nseq          %s\nlast check   %s\noutbox       %d files, %d bytes\n",
		st.AgentID, st.Status, st.Concentrator, st.CAFingerprint, strings.TrimSpace(string(seq)), lastAt, files, size), nil
}
