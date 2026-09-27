// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNewRunWorkDir pins #109: each job gets its own directory under WORKSPACES_DIR, and the
// cleanup removes it together with everything the run wrote.
func TestNewRunWorkDir(t *testing.T) {
	base := filepath.Join(t.TempDir(), "workspaces") // not created yet: the helper must create it

	first, cleanupFirst, err := newRunWorkDir(base, "ws-123")
	if err != nil {
		t.Fatalf("newRunWorkDir() error = %v", err)
	}
	second, cleanupSecond, err := newRunWorkDir(base, "ws-123")
	if err != nil {
		t.Fatalf("newRunWorkDir() error = %v", err)
	}
	defer cleanupSecond()

	if first == second {
		t.Fatalf("two jobs of one workspace share a directory: %s", first)
	}
	for _, dir := range []string{first, second} {
		if filepath.Dir(dir) != base {
			t.Fatalf("dir %s is not directly under WORKSPACES_DIR %s", dir, base)
		}
		if !strings.HasPrefix(filepath.Base(dir), "ws-123-run-") {
			t.Fatalf("dir %s does not carry the workspace ID prefix", dir)
		}
	}

	// Simulate run artifacts, including a nested provider cache.
	if err := os.MkdirAll(filepath.Join(first, ".terraform", "providers"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(first, "stackweaver.auto.tfvars"), []byte("secret = \"x\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cleanupFirst()
	if _, err := os.Stat(first); !os.IsNotExist(err) {
		t.Fatalf("cleanup left %s behind (stat err = %v)", first, err)
	}
	if _, err := os.Stat(second); err != nil {
		t.Fatalf("cleanup of one job removed another job's dir: %v", err)
	}
}
