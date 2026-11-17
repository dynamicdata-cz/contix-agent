// Package identity manages agent and concentrator keys: the TLS key, the
// Ed25519 message-signing key, registration and pinning of the installation key.
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// ErrInsecureKeyFile is returned when a private key file is readable by group or others.
var ErrInsecureKeyFile = errors.New("identity: private key file permissions too open (want 0600)")

const pemType = "PRIVATE KEY"

// GenerateSigningKey creates a new Ed25519 message-signing key.
func GenerateSigningKey() (ed25519.PrivateKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	return priv, err
}

// SaveKey writes key as PKCS#8 PEM with mode 0600. It never overwrites an existing file:
// replacing an identity is a deliberate re-registration, not a side effect.
func SaveKey(path string, key ed25519.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if err := pem.Encode(f, &pem.Block{Type: pemType, Bytes: der}); err != nil {
		f.Close()
		os.Remove(path)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// LoadKey reads an Ed25519 key written by SaveKey. On Unix it refuses files that
// group or others can access, like OpenSSH does.
func LoadKey(path string) (ed25519.PrivateKey, error) {
	if runtime.GOOS != "windows" {
		st, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		if st.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("%w: %s is %#o", ErrInsecureKeyFile, path, st.Mode().Perm())
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != pemType {
		return nil, fmt.Errorf("identity: %s is not a PEM private key", path)
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("identity: %s is not an Ed25519 key", path)
	}
	return priv, nil
}

// Fingerprint returns "SHA256:<base64>" of the raw 32-byte public key (the OpenSSH display
// format, but not the OpenSSH wire encoding, so it differs from ssh-keygen -l).
// Only fingerprints, never key material, leave the host for identification and pinning.
func Fingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}
