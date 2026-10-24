// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/michielvha/stackweaver/core/crypto"
	"github.com/michielvha/stackweaver/core/storage"
)

// memStorage holds objects in memory. The embedded interface is nil on purpose: any call but Put
// and Get is one these tests do not expect, and panics.
type memStorage struct {
	storage.Client
	objects map[string][]byte
}

func (s *memStorage) Put(_ context.Context, key string, data []byte) error {
	s.objects[key] = append([]byte(nil), data...)
	return nil
}

func (s *memStorage) Get(_ context.Context, key string) ([]byte, error) {
	data, ok := s.objects[key]
	if !ok {
		return nil, errors.New("no such object")
	}
	return data, nil
}

// TestPlanFileAtRest pins that the saved plan carried from the plan job to the apply job is
// encrypted in object storage like state, that a plan stored before encryption at rest still
// restores, and that a payload which neither decrypts nor is a plan is refused.
func TestPlanFileAtRest(t *testing.T) {
	atRest, err := crypto.NewCryptoService(bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatalf("NewCryptoService: %v", err)
	}
	plan := []byte("PK\x03\x04 tfplan with a secret value \x00\x01")
	const runID = "run-plan-at-rest"

	write := func(t *testing.T) string {
		t.Helper()
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "plan.out"), plan, 0o600); err != nil {
			t.Fatalf("writing the plan: %v", err)
		}
		return dir
	}
	restored := func(t *testing.T, dir string) []byte {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(dir, "plan.out")) //nolint:gosec // dir is the test's own temp dir
		if err != nil {
			t.Fatalf("reading the restored plan: %v", err)
		}
		return data
	}

	t.Run("the stored plan is encrypted and restores to the original", func(t *testing.T) {
		store := &memStorage{objects: map[string][]byte{}}
		if err := persistPlanFile(t.Context(), store, atRest, runID, write(t)); err != nil {
			t.Fatalf("persistPlanFile: %v", err)
		}
		stored := store.objects[planFileKey(runID)]
		if len(stored) == 0 || bytes.Contains(stored, []byte("secret value")) {
			t.Fatalf("object storage holds the plan in plaintext: %q", stored)
		}
		dir := t.TempDir()
		if err := restorePlanFile(t.Context(), store, atRest, runID, dir); err != nil {
			t.Fatalf("restorePlanFile: %v", err)
		}
		if got := restored(t, dir); !bytes.Equal(got, plan) {
			t.Fatalf("restored plan %q, want %q", got, plan)
		}
	})

	t.Run("a plan stored before encryption at rest still restores", func(t *testing.T) {
		store := &memStorage{objects: map[string][]byte{planFileKey(runID): plan}}
		dir := t.TempDir()
		if err := restorePlanFile(t.Context(), store, atRest, runID, dir); err != nil {
			t.Fatalf("restorePlanFile: %v", err)
		}
		if got := restored(t, dir); !bytes.Equal(got, plan) {
			t.Fatalf("restored plan %q, want %q", got, plan)
		}
	})

	t.Run("a tampered payload is refused", func(t *testing.T) {
		other, err := crypto.NewCryptoService(bytes.Repeat([]byte{4}, 32))
		if err != nil {
			t.Fatalf("NewCryptoService: %v", err)
		}
		store := &memStorage{objects: map[string][]byte{}}
		if err := persistPlanFile(t.Context(), store, other, runID, write(t)); err != nil {
			t.Fatalf("persistPlanFile: %v", err)
		}
		if err := restorePlanFile(t.Context(), store, atRest, runID, t.TempDir()); err == nil {
			t.Fatal("a plan sealed under another key was restored")
		}
	})
}
