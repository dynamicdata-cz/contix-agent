package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunVersion(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"version"}, &out, &errOut); code != 0 {
		t.Fatalf("exit code %d, want 0", code)
	}
	if strings.TrimSpace(out.String()) != version {
		t.Fatalf("got %q, want %q", out.String(), version)
	}
}

func TestRunUnknownRole(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"shell"}, &out, &errOut); code != 2 {
		t.Fatalf("exit code %d, want 2", code)
	}
}

func TestRegisterRequiresURLAndCode(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"concentrator", "register", "--state-dir", t.TempDir()}, &out, &errOut); code != 2 {
		t.Fatalf("exit code %d, want 2", code)
	}
}

func TestStatusNotRegistered(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"concentrator", "status", "--state-dir", t.TempDir()}, &out, &errOut); code != 1 || !strings.Contains(errOut.String(), "not registered") {
		t.Fatalf("exit %d, stderr %q", code, errOut.String())
	}
}
