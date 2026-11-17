package identity

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys", "signing.key")
	key, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveKey(path, key); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		st, _ := os.Stat(path)
		if st.Mode().Perm() != 0o600 {
			t.Fatalf("mode %#o, want 0600", st.Mode().Perm())
		}
	}
	got, err := LoadKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, key) {
		t.Fatal("loaded key differs")
	}
}

func TestSaveNeverOverwrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "signing.key")
	k1, _ := GenerateSigningKey()
	k2, _ := GenerateSigningKey()
	if err := SaveKey(path, k1); err != nil {
		t.Fatal(err)
	}
	if err := SaveKey(path, k2); !errors.Is(err, os.ErrExist) {
		t.Fatalf("err = %v, want os.ErrExist", err)
	}
	got, _ := LoadKey(path)
	if !bytes.Equal(got, k1) {
		t.Fatal("original key was replaced")
	}
}

func TestLoadRefusesOpenPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions")
	}
	path := filepath.Join(t.TempDir(), "signing.key")
	k, _ := GenerateSigningKey()
	if err := SaveKey(path, k); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKey(path); !errors.Is(err, ErrInsecureKeyFile) {
		t.Fatalf("err = %v, want ErrInsecureKeyFile", err)
	}
}

func TestLoadRejectsGarbage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "signing.key")
	if err := os.WriteFile(path, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKey(path); err == nil {
		t.Fatal("garbage accepted")
	}
}

func TestFingerprint(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	fp := Fingerprint(pub)
	if !strings.HasPrefix(fp, "SHA256:") || len(fp) != len("SHA256:")+43 {
		t.Fatalf("fingerprint %q", fp)
	}
	if Fingerprint(pub) != fp {
		t.Fatal("not deterministic")
	}
}
