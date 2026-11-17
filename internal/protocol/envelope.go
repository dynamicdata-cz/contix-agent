// Package protocol defines the CONTIX agent protocol v1 message envelope,
// its canonical form (RFC 8785) and Ed25519 message signatures.
//
// The reference schema lives in CONTIX (packages/shared, Zod) and is exported
// to schema/ as JSON Schema; both repositories verify the shared test vectors
// in testdata/protocol-v1.
package protocol

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Version is the protocol version carried in Envelope.V.
const Version = 1

// MaxAgentIDLen bounds the agent identifier assigned at registration.
const MaxAgentIDLen = 128

// Kind is the message type.
type Kind string

const (
	KindHello    Kind = "hello"
	KindSnapshot Kind = "snapshot"
	KindChange   Kind = "change"
	KindEvidence Kind = "evidence"
	KindFlows    Kind = "flows"
)

// Valid reports whether k is a known message kind.
func (k Kind) Valid() bool {
	switch k {
	case KindHello, KindSnapshot, KindChange, KindEvidence, KindFlows:
		return true
	}
	return false
}

// Envelope is a single signed message from an agent.
// Sig is Ed25519 over the canonical JSON (RFC 8785) of the envelope without "sig".
type Envelope struct {
	V       int             `json:"v"`
	Agent   string          `json:"agent"`
	Seq     uint64          `json:"seq"`
	TS      time.Time       `json:"ts"`
	Kind    Kind            `json:"kind"`
	Payload json.RawMessage `json:"payload"`
	Sig     string          `json:"sig,omitempty"`
}

var (
	// ErrInvalidEnvelope is returned when a message does not satisfy protocol v1.
	ErrInvalidEnvelope = errors.New("protocol: invalid envelope")
	// ErrSignature is returned when a signature is missing, malformed or does not verify.
	ErrSignature = errors.New("protocol: invalid signature")
)

// Validate checks the envelope fields (not the signature).
func (e *Envelope) Validate() error {
	switch {
	case e.V != Version:
		return fmt.Errorf("%w: unsupported version %d", ErrInvalidEnvelope, e.V)
	case e.Agent == "" || len(e.Agent) > MaxAgentIDLen:
		return fmt.Errorf("%w: agent id", ErrInvalidEnvelope)
	case e.Seq == 0:
		return fmt.Errorf("%w: seq must start at 1", ErrInvalidEnvelope)
	case e.TS.IsZero():
		return fmt.Errorf("%w: missing ts", ErrInvalidEnvelope)
	case !e.Kind.Valid():
		return fmt.Errorf("%w: unknown kind %q", ErrInvalidEnvelope, e.Kind)
	}
	p := bytes.TrimSpace(e.Payload)
	if len(p) == 0 || p[0] != '{' {
		return fmt.Errorf("%w: payload must be a JSON object", ErrInvalidEnvelope)
	}
	return nil
}

// SigningBytes returns the canonical bytes covered by the signature.
func (e *Envelope) SigningBytes() ([]byte, error) {
	c := *e
	c.Sig = ""
	raw, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	return Canonicalize(raw)
}

// Sign validates the envelope and sets Sig.
func (e *Envelope) Sign(key ed25519.PrivateKey) error {
	if len(key) != ed25519.PrivateKeySize {
		return fmt.Errorf("%w: bad private key", ErrSignature)
	}
	if err := e.Validate(); err != nil {
		return err
	}
	b, err := e.SigningBytes()
	if err != nil {
		return err
	}
	e.Sig = base64.StdEncoding.EncodeToString(ed25519.Sign(key, b))
	return nil
}

// VerifyRaw verifies a message exactly as it was transmitted: the signature is checked
// over the canonical form of the received JSON (minus "sig"), never over a re-encoded struct,
// so formatting differences between implementations cannot break or forge verification.
// On success the decoded, validated envelope is returned.
func VerifyRaw(raw []byte, pub ed25519.PublicKey) (*Envelope, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: bad public key", ErrSignature)
	}
	canon, err := Canonicalize(raw)
	if err != nil {
		return nil, err
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(canon, &obj); err != nil {
		return nil, fmt.Errorf("%w: not an object", ErrInvalidEnvelope)
	}
	sigRaw, ok := obj["sig"]
	if !ok {
		return nil, fmt.Errorf("%w: missing", ErrSignature)
	}
	var sigB64 string
	if err := json.Unmarshal(sigRaw, &sigB64); err != nil {
		return nil, fmt.Errorf("%w: not a string", ErrSignature)
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("%w: malformed", ErrSignature)
	}
	delete(obj, "sig")
	unsigned, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}
	signed, err := Canonicalize(unsigned)
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(pub, signed, sig) {
		return nil, ErrSignature
	}
	var e Envelope
	dec := json.NewDecoder(bytes.NewReader(canon))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&e); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidEnvelope, err)
	}
	if err := e.Validate(); err != nil {
		return nil, err
	}
	return &e, nil
}
