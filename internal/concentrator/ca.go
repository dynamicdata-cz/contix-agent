package concentrator

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"slices"
	"time"
)

// Zone CA: the concentrator issues its own TLS server certificate and the client certificates
// of agents in its zone. Agents pin this CA (fingerprint delivered with the enrollment token),
// so a stolen agent certificate is useless outside the zone and CONTIX never holds zone keys.

const (
	caValidity     = 10 * 365 * 24 * time.Hour
	serverValidity = 825 * 24 * time.Hour
	agentValidity  = 365 * 24 * time.Hour
	renewBefore    = 30 * 24 * time.Hour
)

func serial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
}

func writeKey(path string, key crypto.Signer) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	return writeFileAtomic(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600)
}

func readKey(path string) (crypto.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	b, _ := pem.Decode(data)
	if b == nil {
		return nil, fmt.Errorf("concentrator: %s is not PEM", path)
	}
	k, err := x509.ParsePKCS8PrivateKey(b.Bytes)
	if err != nil {
		return nil, err
	}
	s, ok := k.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("concentrator: %s: unsupported key", path)
	}
	return s, nil
}

func readCert(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	b, _ := pem.Decode(data)
	if b == nil || b.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("concentrator: %s is not a PEM certificate", path)
	}
	return x509.ParseCertificate(b.Bytes)
}

func certPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// CAFingerprint returns the SHA-256 of the CA certificate (hex), which agents pin.
func CAFingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}

// EnsureCA loads the zone CA or creates it on first use.
func EnsureCA(p Paths, zone, concentratorID string) (*x509.Certificate, crypto.Signer, error) {
	if c, err := readCert(p.CACert()); err == nil {
		k, err := readKey(p.CAKey())
		if err != nil {
			return nil, nil, err
		}
		return c, k, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	sn, err := serial()
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	tpl := &x509.Certificate{
		SerialNumber:          sn,
		Subject:               pkix.Name{Organization: []string{"CONTIX"}, OrganizationalUnit: []string{"zone " + zone}, CommonName: "CONTIX zone CA " + concentratorID},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(caValidity),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, key.Public(), key)
	if err != nil {
		return nil, nil, err
	}
	if err := writeKey(p.CAKey(), key); err != nil {
		return nil, nil, err
	}
	if err := writeFileAtomic(p.CACert(), certPEM(der), 0o644); err != nil {
		return nil, nil, err
	}
	c, err := x509.ParseCertificate(der)
	return c, key, err
}

// EnsureServerCert (re)issues the concentrator's TLS certificate when missing, close to expiry
// or when the requested host names / addresses changed.
func EnsureServerCert(p Paths, ca *x509.Certificate, caKey crypto.Signer, hosts []string) error {
	if c, err := readCert(p.ServerCert()); err == nil && time.Until(c.NotAfter) > renewBefore && sameHosts(c, hosts) && chainLen(p.ServerCert()) >= 2 {
		if _, err := readKey(p.ServerKey()); err == nil {
			return nil
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	sn, err := serial()
	if err != nil {
		return err
	}
	now := time.Now()
	tpl := &x509.Certificate{
		SerialNumber: sn,
		Subject:      pkix.Name{CommonName: hosts[0]},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(serverValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tpl.IPAddresses = append(tpl.IPAddresses, ip)
		} else {
			tpl.DNSNames = append(tpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca, key.Public(), caKey)
	if err != nil {
		return err
	}
	if err := writeKey(p.ServerKey(), key); err != nil {
		return err
	}
	// leaf + zone CA: agents pin the CA by fingerprint, so the server presents it in the handshake
	return writeFileAtomic(p.ServerCert(), append(certPEM(der), certPEM(ca.Raw)...), 0o644)
}

// chainLen counts PEM certificates in a file (server.crt from older versions holds only the leaf).
func chainLen(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	n := 0
	for {
		var b *pem.Block
		b, data = pem.Decode(data)
		if b == nil {
			return n
		}
		if b.Type == "CERTIFICATE" {
			n++
		}
	}
}

func sameHosts(c *x509.Certificate, hosts []string) bool {
	have := append([]string{}, c.DNSNames...)
	for _, ip := range c.IPAddresses {
		have = append(have, ip.String())
	}
	want := make([]string, 0, len(hosts))
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			h = ip.String()
		}
		want = append(want, h)
	}
	slices.Sort(have)
	slices.Sort(want)
	return slices.Equal(have, want)
}

// SignAgentCSR issues a client certificate whose CommonName is the CONTIX agent ID.
// The CSR's own signature is checked, so only the holder of the key gets a certificate for it.
func SignAgentCSR(ca *x509.Certificate, caKey crypto.Signer, csrPEM []byte, agentID string) ([]byte, error) {
	b, _ := pem.Decode(csrPEM)
	if b == nil || b.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("concentrator: CSR must be PEM \"CERTIFICATE REQUEST\"")
	}
	csr, err := x509.ParseCertificateRequest(b.Bytes)
	if err != nil {
		return nil, err
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("concentrator: CSR signature: %w", err)
	}
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tpl := &x509.Certificate{
		SerialNumber: sn,
		Subject:      pkix.Name{CommonName: agentID},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(agentValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca, csr.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	return certPEM(der), nil
}
