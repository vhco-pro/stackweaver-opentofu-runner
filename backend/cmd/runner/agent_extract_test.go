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

// makeTarGzRaw builds a tarball preserving entry order and allowing arbitrary
// (including unsafe) names, which the map-based helper above cannot express.
func makeTarGzRaw(t *testing.T, entries [][2]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		name, content := e[0], e[1]
		if err := tw.WriteHeader(&tar.Header{
			Name: name, Mode: 0o600, Size: int64(len(content)), Typeflag: tar.TypeReg,
		}); err != nil {
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

// unsafeEntryNames are the names archive.SafeEntryName must reject. Both runner
// extractors route every entry through it, so neither may write outside destDir.
var unsafeEntryNames = []string{
	"../escape.tf",
	"../../escape.tf",
	"sub/../../escape.tf",
	"/etc/passwd",
	"",
}

// TestExtractors_RejectTraversal is the regression test for the two go/zipslip
// alerts on stackweaver-opentofu-runner (backend/cmd/runner/main.go and
// agent_mode.go). Both execution paths are covered deliberately: the queue-mode
// extractor and the agent-mode one are separate functions, and a fix verified
// against only one of them is a recurring trap in this repo.
func TestExtractors_RejectTraversal(t *testing.T) {
	extractors := map[string]func([]byte, string) error{
		"queue-mode/extractTarGz":         extractTarGz,
		"agent-mode/extractTarGzForAgent": extractTarGzForAgent,
	}
	for label, extract := range extractors {
		for _, name := range unsafeEntryNames {
			t.Run(label+"/"+name, func(t *testing.T) {
				dest := t.TempDir()
				parent := filepath.Dir(dest)
				data := makeTarGzRaw(t, [][2]string{{name, "pwned"}})

				if err := extract(data, dest); err == nil {
					t.Fatalf("expected an error for unsafe entry %q, got nil", name)
				}

				// The guarantee that matters is not the error, it is that nothing
				// was written outside destDir.
				if _, err := os.Stat(filepath.Join(parent, "escape.tf")); err == nil {
					t.Errorf("entry %q escaped destDir: wrote %s", name, filepath.Join(parent, "escape.tf"))
				}
			})
		}
	}
}

// TestExtractors_AcceptOrdinaryEntries guards the other direction. SafeEntryName
// uses filepath.IsLocal, which is stricter than the previous post-join prefix
// check, so this pins the names that must keep working - in particular the "./"
// and "." forms that tar writers emit for the archive root.
func TestExtractors_AcceptOrdinaryEntries(t *testing.T) {
	extractors := map[string]func([]byte, string) error{
		"queue-mode/extractTarGz":         extractTarGz,
		"agent-mode/extractTarGzForAgent": extractTarGzForAgent,
	}
	for label, extract := range extractors {
		t.Run(label, func(t *testing.T) {
			dest := t.TempDir()
			data := makeTarGzRaw(t, [][2]string{
				{"./main.tf", "a"},
				{"modules/sub/vars.tf", "b"},
				{"a//b.tf", "c"},
				{"nested/../flat.tf", "d"},
				{".terraform.lock.hcl", "e"},
			})
			if err := extract(data, dest); err != nil {
				t.Fatalf("ordinary tarball rejected: %v", err)
			}
			for path, want := range map[string]string{
				"main.tf":             "a",
				"modules/sub/vars.tf": "b",
				"a/b.tf":              "c",
				"flat.tf":             "d",
				".terraform.lock.hcl": "e",
			} {
				got, err := os.ReadFile(filepath.Join(dest, path)) //nolint:gosec // test-controlled path
				if err != nil {
					t.Errorf("read %s: %v", path, err)
					continue
				}
				if string(got) != want {
					t.Errorf("%s: got %q want %q", path, got, want)
				}
			}
		})
	}
}
