// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Regression test for the queue-mode runner wedging an auto-applied run at `applying`.
//
// A run that auto-applies (a per-run `auto-apply: true`, or a VCS push in a workspace with
// auto-apply on) moves from its plan straight to `applying` inside the runner, and the
// orchestrator must then dispatch its apply phase. The orchestrator can only claim a run whose
// dispatch claim is NULL, so the runner clears the claim the plan dispatch consumed.
//
// The clear was a database UPDATE only. The run struct the job holds in memory still carried the
// old claim, and every job ends with a full Save of that struct, which wrote the stale claim
// straight back. The orchestrator never claimed the apply phase and the run sat at `applying`
// until the timeout reaper failed it. The agent finalize path (runner_agent.go) has always reset
// the in-memory field for exactly this reason; this path did not.
//
// The test replays the three writes in the order the job makes them and then asks the question
// the orchestrator asks.
//
// Gated behind `integration`; skips unless $TEST_DATABASE_URL is set. Cleanup is row-scoped.

//go:build integration

package main

import (
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/dbtest"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"gorm.io/gorm"
)

func TestAutoApplyReleasesTheDispatchClaimForTheApplyPhase(t *testing.T) {
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping integration test")
	}
	db, err := dbtest.Open(t, dbURL, &gorm.Config{})
	if err != nil {
		t.Fatalf("connect test db: %v", err)
	}
	if err := db.AutoMigrate(&models.Organization{}, &models.Project{}, &models.Workspace{}, &models.Run{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	sfx := uuid.NewString()[:8]

	org := &models.Organization{ID: uuid.New(), Name: "aadispatch-" + sfx}
	project := &models.Project{ID: uuid.New(), OrganizationID: org.ID, Name: "proj-" + sfx}
	workspace := &models.Workspace{ID: "ws-" + sfx + "aadisp0", ProjectID: project.ID, Name: "ws-" + sfx}
	planDispatchedAt := time.Now().Add(-10 * time.Second)
	seeded := &models.Run{
		ID:                 "run-" + sfx + "aadisp",
		WorkspaceID:        workspace.ID,
		Status:             models.RunStatusPlanning,
		Operation:          models.RunOperationPlanAndApply,
		AutoApply:          true,
		AutoApplyAfterPlan: true,
		DispatchedAt:       &planDispatchedAt, // the claim the orchestrator took to dispatch the plan
	}
	for _, obj := range []any{org, project, workspace, seeded} {
		if err := db.Create(obj).Error; err != nil {
			t.Fatalf("seed %T: %v", obj, err)
		}
	}
	t.Cleanup(func() {
		db.Where("id = ?", seeded.ID).Delete(&models.Run{})
		db.Where("id = ?", workspace.ID).Delete(&models.Workspace{})
		db.Where("id = ?", project.ID).Delete(&models.Project{})
		db.Where("id = ?", org.ID).Delete(&models.Organization{})
	})

	runRepo := repository.NewRunRepository(db)

	// The job loads the run after the plan dispatch claimed it, so its copy carries the claim.
	run, err := runRepo.GetByID(seeded.ID)
	if err != nil {
		t.Fatalf("loading run: %v", err)
	}
	if run.DispatchedAt == nil {
		t.Fatal("precondition: the loaded run must carry the plan dispatch claim")
	}

	// 1. The plan finished and the run auto-applies: the transition to `applying`.
	now := time.Now()
	run.Status = models.RunStatusApplying
	run.ApplyStartedAt = &now
	if ok, err := runRepo.CompleteIfNotCanceled(run); err != nil || !ok {
		t.Fatalf("transition to applying: ok=%v err=%v", ok, err)
	}

	// 2. The runner releases the claim so the orchestrator can dispatch the apply phase.
	if err := releaseDispatchClaim(runRepo, run); err != nil {
		t.Fatalf("releaseDispatchClaim: %v", err)
	}

	// 3. The job ends with its guarded full save of the same struct.
	if ok, err := runRepo.CompleteIfNotCanceled(run); err != nil || !ok {
		t.Fatalf("final save: ok=%v err=%v", ok, err)
	}

	// The orchestrator's question: can the apply phase be claimed?
	claimed, err := runRepo.ClaimForDispatch(run.ID)
	if err != nil {
		t.Fatalf("ClaimForDispatch: %v", err)
	}
	if !claimed {
		t.Fatal("the apply phase cannot be claimed: the job's final save wrote the stale plan dispatch claim back, so the run would sit at `applying` until the timeout reaper fails it")
	}
}
