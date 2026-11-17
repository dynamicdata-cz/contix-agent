package concentrator

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/dynamicdata-cz/contix-agent/internal/protocol"
	"github.com/dynamicdata-cz/contix-agent/internal/spool"
)

// Limits of the agent-facing API.
const (
	maxEnrollBytes = 64 << 10
	maxBatchBytes  = 8 << 20
	maxBatchMsgs   = 1000
)

// AgentEnrollRequest is sent by an agent with a zone enrollment token.
type AgentEnrollRequest struct {
	Token     string `json:"token"`
	HostID    string `json:"hostId"`
	Hostname  string `json:"hostname"`
	OS        string `json:"os"`
	Version   string `json:"version"`
	PublicKey string `json:"publicKey"` // Ed25519 message-signing key, base64
	CSR       string `json:"csr"`       // PEM certificate request for the mTLS client certificate
}

// AgentEnrollResponse carries the CONTIX agent ID and the mTLS client certificate.
type AgentEnrollResponse struct {
	AgentID     string `json:"agentId"`
	Status      string `json:"status"`
	Certificate string `json:"certificate"`
	CA          string `json:"ca"`
}

// Upstream is the part of the CONTIX client the server needs (mockable in tests).
type Upstream interface {
	RegisterAgent(ctx context.Context, a AgentInfo) (*AgentRegistration, error)
}

// Server is the agent-facing HTTPS endpoint of the concentrator.
type Server struct {
	Registry *Registry
	Queue    *spool.Queue
	Upstream Upstream
	CA       *x509.Certificate
	CAKey    crypto.Signer
	Log      *slog.Logger
}

func writeJSONResp(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func httpError(w http.ResponseWriter, status int, msg string) {
	writeJSONResp(w, status, map[string]string{"error": msg})
}

// Handler returns the routes: GET /v1/health, POST /v1/enroll (token), POST /v1/batch (mTLS).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", func(w http.ResponseWriter, _ *http.Request) { writeJSONResp(w, 200, map[string]string{"status": "ok"}) })
	mux.HandleFunc("POST /v1/enroll", s.enroll)
	mux.HandleFunc("POST /v1/batch", s.batch)
	return mux
}

func (s *Server) enroll(w http.ResponseWriter, r *http.Request) {
	var req AgentEnrollRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxEnrollBytes)).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	now := time.Now()
	if err := s.Registry.CheckToken(req.Token, now); err != nil {
		time.Sleep(time.Second) // slow down token guessing
		httpError(w, http.StatusUnauthorized, err.Error())
		return
	}
	if k, err := base64.StdEncoding.DecodeString(req.PublicKey); err != nil || len(k) != 32 || req.HostID == "" || req.Hostname == "" || req.CSR == "" {
		httpError(w, http.StatusBadRequest, "hostId, hostname, publicKey (32 B base64) and csr are required")
		return
	}
	reg, err := s.Upstream.RegisterAgent(r.Context(), AgentInfo{HostID: req.HostID, Hostname: req.Hostname, OS: req.OS, Version: req.Version, PublicKey: req.PublicKey})
	if err != nil {
		s.Log.Error("agent registration at CONTIX failed", "hostname", req.Hostname, "err", err)
		httpError(w, http.StatusBadGateway, "CONTIX unavailable or refused the registration")
		return
	}
	if reg.Status == "blocked" {
		httpError(w, http.StatusForbidden, "agent is blocked in CONTIX")
		return
	}
	certPEM, err := SignAgentCSR(s.CA, s.CAKey, []byte(req.CSR), reg.AgentID)
	if err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.Registry.ConsumeToken(req.Token, now); err != nil {
		httpError(w, http.StatusUnauthorized, err.Error())
		return
	}
	if err := s.Registry.PutAgent(reg.AgentID, AgentRecord{PublicKey: req.PublicKey, HostID: req.HostID, Hostname: req.Hostname, Enrolled: now}); err != nil {
		httpError(w, http.StatusInternalServerError, "cannot store agent")
		return
	}
	s.Log.Info("agent enrolled", "agent", reg.AgentID, "hostname", req.Hostname, "status", reg.Status)
	writeJSONResp(w, http.StatusOK, AgentEnrollResponse{AgentID: reg.AgentID, Status: reg.Status, Certificate: string(certPEM), CA: string(certPEMFrom(s.CA))})
}

func (s *Server) batch(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
		httpError(w, http.StatusUnauthorized, "client certificate required")
		return
	}
	agentID := r.TLS.VerifiedChains[0][0].Subject.CommonName
	pub, ok := s.Registry.AgentKey(agentID)
	if !ok {
		httpError(w, http.StatusForbidden, "unknown agent")
		return
	}
	var req struct {
		Messages []json.RawMessage `json:"messages"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBatchBytes)).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if len(req.Messages) == 0 || len(req.Messages) > maxBatchMsgs {
		httpError(w, http.StatusBadRequest, "1..1000 messages per batch")
		return
	}
	type rejected struct {
		Index  int    `json:"index"`
		Reason string `json:"reason"`
	}
	var ok2 []json.RawMessage
	var rej []rejected
	for i, m := range req.Messages {
		env, err := protocol.VerifyRaw(m, pub)
		switch {
		case err != nil:
			rej = append(rej, rejected{i, err.Error()})
		case env.Agent != agentID:
			rej = append(rej, rejected{i, "agent id does not match the client certificate"})
		default:
			ok2 = append(ok2, m)
		}
	}
	if len(ok2) > 0 {
		if err := s.Queue.Append(ok2); err != nil {
			if errors.Is(err, spool.ErrQueueFull) {
				w.Header().Set("Retry-After", "300")
				httpError(w, http.StatusServiceUnavailable, "queue full, retry later")
				return
			}
			s.Log.Error("queue append failed", "err", err)
			httpError(w, http.StatusInternalServerError, "cannot queue messages")
			return
		}
	}
	writeJSONResp(w, http.StatusOK, map[string]any{"queued": len(ok2), "rejected": rej})
}

// TLSConfig requires TLS 1.3, presents the server certificate and verifies agent certificates
// against the zone CA when given (enrollment works without one).
func TLSConfig(p Paths, ca *x509.Certificate) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(p.ServerCert(), p.ServerKey())
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    pool,
	}, nil
}

func certPEMFrom(c *x509.Certificate) []byte { return certPEM(c.Raw) }
