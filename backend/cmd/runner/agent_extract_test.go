// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

func makeTarGz(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, content := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestExtractTarGzForAgent_NormalExtraction covers AUD-073: the agent extractor now caps each file
// at 100MB via io.LimitReader (matching the platform runner). This confirms the cap does not
// truncate or corrupt ordinary files - a well-under-cap tarball extracts byte-for-byte.
func TestExtractTarGzForAgent_NormalExtraction(t *testing.T) {
	dest := t.TempDir()
	data := makeTarGz(t, map[string]string{
		"main.tf":       "resource \"null_resource\" \"a\" {}\n",
		"sub/vars.tf":   "variable \"x\" {}\n",
		"large-ish.txt": string(bytes.Repeat([]byte("z"), 5<<20)), // 5MB, well under the 100MB cap
	})
	if err := extractTarGzForAgent(data, dest); err != nil {
		t.Fatalf("extract: %v", err)
	}
	for name, want := range map[string]string{
		"main.tf":     "resource \"null_resource\" \"a\" {}\n",
		"sub/vars.tf": "variable \"x\" {}\n",
	} {
		got, err := os.ReadFile(filepath.Join(dest, name)) //nolint:gosec // test-controlled path
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if string(got) != want {
			t.Errorf("%s: content mismatch", name)
		}
	}
	// the 5MB file must be intact (under the cap, so no truncation)
	big, err := os.ReadFile(filepath.Join(dest, "large-ish.txt")) //nolint:gosec // test-controlled path
	if err != nil {
		t.Fatalf("read large file: %v", err)
	}
	if len(big) != 5<<20 {
		t.Errorf("large file truncated: got %d bytes, want %d", len(big), 5<<20)
	}
}
