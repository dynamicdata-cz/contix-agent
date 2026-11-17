// Package spool is an append-only on-disk message queue shared by the agent (outbox)
// and the concentrator (forwarding queue).
package spool

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/dynamicdata-cz/contix-agent/internal/fsutil"
)

// ErrQueueFull is returned when accepting a batch would exceed the queue size limit.
// The agent keeps its data and retries later, so nothing is silently dropped.
var ErrQueueFull = errors.New("spool: queue full")

// Queue is an append-only on-disk queue: one file per appended batch, one signed
// message per line, exactly as received (compacted). Files are removed only after CONTIX
// accepted the forwarded batch.
type Queue struct {
	dir      string
	maxBytes int64
	maxAge   time.Duration
	mu       sync.Mutex
}

// NewQueue opens (and creates) the queue directory.
func NewQueue(dir string, maxBytes int64, maxAge time.Duration) (*Queue, error) {
	if err := os.MkdirAll(filepath.Join(dir, "dead"), 0o700); err != nil {
		return nil, err
	}
	return &Queue{dir: dir, maxBytes: maxBytes, maxAge: maxAge}, nil
}

type qfile struct {
	name string
	size int64
	mod  time.Time
}

func (q *Queue) list() ([]qfile, int64, error) {
	ents, err := os.ReadDir(q.dir)
	if err != nil {
		return nil, 0, err
	}
	var out []qfile
	var total int64
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".jsonl") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, qfile{e.Name(), info.Size(), info.ModTime()})
		total += info.Size()
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name }) // names start with a timestamp
	return out, total, nil
}

// Append durably stores messages as one queue file.
func (q *Queue) Append(msgs []json.RawMessage) error {
	var buf bytes.Buffer
	for _, m := range msgs {
		if err := json.Compact(&buf, m); err != nil {
			return err
		}
		buf.WriteByte('\n')
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	_, total, err := q.list()
	if err != nil {
		return err
	}
	if total+int64(buf.Len()) > q.maxBytes {
		return ErrQueueFull
	}
	rnd := make([]byte, 4)
	_, _ = rand.Read(rnd)
	name := fmt.Sprintf("%020d-%s.jsonl", time.Now().UnixNano(), hex.EncodeToString(rnd))
	return fsutil.WriteFileAtomic(filepath.Join(q.dir, name), buf.Bytes(), 0o600)
}

// Next returns the oldest whole files up to maxMsgs messages / maxBytes (always at least one file).
func (q *Queue) Next(maxMsgs int, maxBytes int64) ([]string, []json.RawMessage, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	files, _, err := q.list()
	if err != nil {
		return nil, nil, err
	}
	var names []string
	var msgs []json.RawMessage
	var size int64
	for _, f := range files {
		lines, err := readLines(filepath.Join(q.dir, f.name))
		if err != nil {
			return nil, nil, err
		}
		if len(names) > 0 && (len(msgs)+len(lines) > maxMsgs || size+f.size > maxBytes) {
			break
		}
		names = append(names, f.name)
		msgs = append(msgs, lines...)
		size += f.size
	}
	return names, msgs, nil
}

func readLines(path string) ([]json.RawMessage, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []json.RawMessage
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 16<<20)
	for sc.Scan() {
		if line := bytes.TrimSpace(sc.Bytes()); len(line) > 0 {
			out = append(out, json.RawMessage(append([]byte(nil), line...)))
		}
	}
	return out, sc.Err()
}

// Done removes forwarded files.
func (q *Queue) Done(names []string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	for _, n := range names {
		if err := os.Remove(filepath.Join(q.dir, filepath.Base(n))); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

// Dead moves files CONTIX permanently refused (malformed) aside for inspection.
func (q *Queue) Dead(names []string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	for _, n := range names {
		n = filepath.Base(n)
		if err := os.Rename(filepath.Join(q.dir, n), filepath.Join(q.dir, "dead", n)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

// Prune deletes files older than the retention period; returns how many were removed.
func (q *Queue) Prune(now time.Time) (int, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	files, _, err := q.list()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, f := range files {
		if now.Sub(f.mod) > q.maxAge {
			if err := os.Remove(filepath.Join(q.dir, f.name)); err == nil {
				n++
			}
		}
	}
	return n, nil
}

// Stats returns the number of queued files and their total size.
func (q *Queue) Stats() (int, int64) {
	q.mu.Lock()
	defer q.mu.Unlock()
	files, total, _ := q.list()
	return len(files), total
}
