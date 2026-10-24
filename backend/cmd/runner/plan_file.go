// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"

	"github.com/michielvha/stackweaver/core/crypto"
	"github.com/michielvha/stackweaver/core/storage"
)

// planFileKey is where a run's saved plan waits between its plan job and its apply job.
func planFileKey(runID string) string {
	return fmt.Sprintf("runs/%s/plan.out", runID)
}

// persistPlanFile stores the saved plan in dir for the apply job, encrypted at rest under the
// same key as state: a plan file carries the run's variables and planned values, sensitive ones
// included.
func persistPlanFile(ctx context.Context, store storage.Client, atRest *crypto.CryptoService, runID, dir string) error {
	data, err := os.ReadFile(filepath.Join(dir, "plan.out")) //nolint:gosec // plan.out is inside the run's own workspace dir
	if err != nil {
		return fmt.Errorf("reading the saved plan: %w", err)
	}
	sealed, err := atRest.EncryptAtRest(data)
	if err != nil {
		return fmt.Errorf("sealing the saved plan: %w", err)
	}
	if err := store.Put(ctx, planFileKey(runID), sealed); err != nil {
		return fmt.Errorf("storing the saved plan: %w", err)
	}
	return nil
}

// restorePlanFile writes the plan the plan job stored back into dir. A plan stored before
// encryption at rest is still accepted: a plan file is binary, while a sealed one is base64 text.
func restorePlanFile(ctx context.Context, store storage.Client, atRest *crypto.CryptoService, runID, dir string) error {
	data, err := store.Get(ctx, planFileKey(runID))
	if err != nil {
		return fmt.Errorf("fetching the saved plan for run %s: %w", runID, err)
	}
	plan, err := atRest.DecryptAtRest(data, isUnsealedPlan)
	if err != nil {
		return fmt.Errorf("opening the saved plan for run %s: %w", runID, err)
	}
	return os.WriteFile(filepath.Join(dir, "plan.out"), plan, 0o600) //nolint:gosec // plan.out is inside the run's own workspace dir
}

// isUnsealedPlan reports whether data was stored as it is rather than sealed: sealed payloads
// are base64 text, and a plan file is not.
func isUnsealedPlan(data []byte) bool {
	_, err := base64.StdEncoding.DecodeString(string(data))
	return err != nil
}
