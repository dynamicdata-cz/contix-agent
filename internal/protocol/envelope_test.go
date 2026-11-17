package protocol

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var update = flag.Bool("update", false, "regenerate testdata/protocol-v1 test vectors")

// testKey is a fixed, publicly known key used ONLY for test vectors shared with CONTIX.
func testKey() ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	return ed25519.NewKeyFromSeed(seed)
}

func sample() Envelope {
	return Envelope{
		V:       Version,
		Agent:   "a8f3c2d1-example",
		Seq:     18234,
		TS:      time.Date(2026, 11, 17, 8, 12, 44, 0, time.UTC),
		Kind:    KindChange,
		Payload: json.RawMessage(`{"module":"ports","op":"add","item":{"port":8443,"proto":"tcp","process":"contix-agent"},"detected":"2026-11-17T08:12:40Z","note":"Příliš žluťoučký kůň <&>"}`),
	}
}

func signed(t *testing.T) []byte {
	t.Helper()
	e := sample()
	if err := e.Sign(testKey()); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestKindValid(t *testing.T) {
	for _, k := range []Kind{KindHello, KindSnapshot, KindChange, KindEvidence, KindFlows} {
		if !k.Valid() {
			t.Errorf("%q should be valid", k)
		}
	}
	if Kind("exec").Valid() {
		t.Error(`"exec" must not be a valid kind`)
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	raw := signed(t)
	e, err := VerifyRaw(raw, testKey().Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	if e.Seq != 18234 || e.Kind != KindChange {
		t.Fatalf("decoded %+v", e)
	}
}

func TestVerifySurvivesReformatting(t *testing.T) {
	// A concentrator or proxy may re-serialize JSON: whitespace, key order and escapes must not matter.
	var obj map[string]any
	if err := json.Unmarshal(signed(t), &obj); err != nil {
		t.Fatal(err)
	}
	pretty, err := json.MarshalIndent(obj, "", "    ") // Go escapes <, > and & as < etc.
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyRaw(pretty, testKey().Public().(ed25519.PublicKey)); err != nil {
		t.Fatalf("reformatted message rejected: %v", err)
	}
}

func TestVerifyRejectsTampering(t *testing.T) {
	pub := testKey().Public().(ed25519.PublicKey)
	raw := string(signed(t))
	other := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))

	cases := map[string]struct {
		msg string
		key ed25519.PublicKey
		err error
	}{
		"changed payload": {strings.Replace(raw, `"port":8443`, `"port":8444`, 1), pub, ErrSignature},
		"changed seq":     {strings.Replace(raw, `"seq":18234`, `"seq":18235`, 1), pub, ErrSignature},
		"wrong key":       {raw, other.Public().(ed25519.PublicKey), ErrSignature},
		"missing sig":     {`{"v":1,"agent":"a","seq":1,"ts":"2026-11-17T08:12:44Z","kind":"hello","payload":{}}`, pub, ErrSignature},
		"garbage sig":     {strings.Replace(raw, `"sig":"`, `"sig":"!!`, 1), pub, ErrSignature},
		"added field":     {strings.Replace(raw, `{"v":1`, `{"cmd":"rm -rf /","v":1`, 1), pub, ErrSignature},
		"duplicate key":   {strings.Replace(raw, `"seq":18234`, `"seq":18234,"seq":1`, 1), pub, ErrNotCanonicalizable},
	}
	for name, c := range cases {
		if _, err := VerifyRaw([]byte(c.msg), c.key); !errors.Is(err, c.err) {
			t.Errorf("%s: err = %v, want %v", name, err, c.err)
		}
	}
}

func TestVerifyRejectsUnknownFieldEvenIfSigned(t *testing.T) {
	// A message signed with an extra top-level field is still not a valid v1 envelope.
	key := testKey()
	unsigned := `{"v":1,"agent":"a","seq":1,"ts":"2026-11-17T08:12:44Z","kind":"hello","payload":{},"cmd":"x"}`
	canon, err := Canonicalize([]byte(unsigned))
	if err != nil {
		t.Fatal(err)
	}
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(key, canon))
	msg := strings.TrimSuffix(unsigned, "}") + `,"sig":"` + sig + `"}`
	if _, err := VerifyRaw([]byte(msg), key.Public().(ed25519.PublicKey)); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("err = %v, want ErrInvalidEnvelope", err)
	}
}

func TestValidate(t *testing.T) {
	mut := map[string]func(*Envelope){
		"version":    func(e *Envelope) { e.V = 2 },
		"agent":      func(e *Envelope) { e.Agent = "" },
		"agent len":  func(e *Envelope) { e.Agent = strings.Repeat("a", MaxAgentIDLen+1) },
		"seq":        func(e *Envelope) { e.Seq = 0 },
		"ts":         func(e *Envelope) { e.TS = time.Time{} },
		"kind":       func(e *Envelope) { e.Kind = "exec" },
		"payload":    func(e *Envelope) { e.Payload = json.RawMessage(`[1,2]`) },
		"no payload": func(e *Envelope) { e.Payload = nil },
	}
	for name, f := range mut {
		e := sample()
		f(&e)
		if err := e.Sign(testKey()); !errors.Is(err, ErrInvalidEnvelope) {
			t.Errorf("%s: err = %v, want ErrInvalidEnvelope", name, err)
		}
	}
}

// vector is the shared test vector format verified by both contix-agent (Go) and CONTIX (TypeScript).
type vector struct {
	Description string          `json:"description"`
	PublicKey   string          `json:"publicKey"`
	Canonical   string          `json:"canonical"`
	Message     json.RawMessage `json:"message"`
}

func TestSharedVector(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "protocol-v1", "change-signed.json")
	key := testKey()
	if *update {
		e := sample()
		if err := e.Sign(key); err != nil {
			t.Fatal(err)
		}
		canon, _ := e.SigningBytes()
		msg, _ := json.Marshal(e)
		v := vector{
			Description: "Protocol v1 change message signed with the PUBLIC TEST KEY (seed 0x00..0x1f). Never use this key outside tests.",
			PublicKey:   base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey)),
			Canonical:   string(canon),
			Message:     msg,
		}
		var out strings.Builder
		enc := json.NewEncoder(&out)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		if err := enc.Encode(v); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(out.String()), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run: go test ./internal/protocol -update)", err)
	}
	var v vector
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	pubBytes, _ := base64.StdEncoding.DecodeString(v.PublicKey)
	e, err := VerifyRaw(v.Message, ed25519.PublicKey(pubBytes))
	if err != nil {
		t.Fatalf("shared vector does not verify: %v", err)
	}
	canon, _ := e.SigningBytes()
	if string(canon) != v.Canonical {
		t.Fatalf("canonical form changed:\n got  %s\n want %s", canon, v.Canonical)
	}
}
