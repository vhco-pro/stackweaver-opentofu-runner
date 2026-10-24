// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// What the platform runner downloads for a run that names a configuration version uploaded to
// another workspace (#916). The API refuses to create such a run, but a run row written before
// it did may name one, and the runner is where the uploaded code is fetched from storage and
// planned: it must not be.
//
// The defect this test was written against: the runner loaded the configuration version by
// identifier alone and downloaded its archive, whatever workspace it had been uploaded to.
//
// This is the queue-mode half. A self-hosted runner gets its configuration from the API's
// artifacts endpoint instead; see TestRunnerRunArtifacts_ConfigurationVersionOfAnotherWorkspace
// in internal/api/v2/handlers.
//
// The test drives processJob up to the download with a storage client that records what it is
// asked for and holds nothing, so a job stops there either way. Gated behind `integration`;
// skips unless $TEST_DATABASE_URL is set. Cleanup is scoped to the fixture's own rows. Run with:
//
//	go test -tags integration ./cmd/runner/ -run TestProcessJob_ConfigurationVersion

//go:build integration

package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"testing"

	"github.com/google/uuid"
	"github.com/michielvha/stackweaver/core/dbtest"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/storage"
	"gorm.io/gorm"
)

// recordingStorage records the keys it is asked for and holds no object. The embedded interface
// is nil on purpose: any call but Get is one this test does not expect, and panics.
type recordingStorage struct {
	storage.Client
	asked []string
}

func (s *recordingStorage) Get(_ context.Context, key string) ([]byte, error) {
	s.asked = append(s.asked, key)
	return nil, errors.New("recordingStorage holds no objects")
}

func TestProcessJob_ConfigurationVersionOfAnotherWorkspace(t *testing.T) {
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping integration test")
	}
	db, err := dbtest.Open(t, dbURL, &gorm.Config{})
	if err != nil {
		t.Fatalf("connecting to the test database: %v", err)
	}
	if err := db.AutoMigrate(&models.Organization{}, &models.Project{}, &models.Workspace{}, &models.ConfigurationVersion{}, &models.Run{}); err != nil {
		t.Fatalf("migrating the tables: %v", err)
	}
	t.Setenv("WORKSPACES_DIR", t.TempDir())
	sfx := uuid.NewString()[:8]

	org := &models.Organization{ID: uuid.New(), Name: "runcv-a-" + sfx}
	otherOrg := &models.Organization{ID: uuid.New(), Name: "runcv-b-" + sfx}
	project := &models.Project{ID: uuid.New(), OrganizationID: org.ID, Name: "runcv-proj-" + sfx}
	otherProject := &models.Project{ID: uuid.New(), OrganizationID: otherOrg.ID, Name: "runcv-proj-" + sfx}
	workspace := &models.Workspace{ID: "ws-" + sfx + "9160000", ProjectID: project.ID, Name: "runcv-ws"}
	otherWorkspace := &models.Workspace{ID: "ws-" + sfx + "9161111", ProjectID: otherProject.ID, Name: "runcv-ws"}
	version := func(suffix, workspaceID string) *models.ConfigurationVersion {
		return &models.ConfigurationVersion{ID: "cv-" + sfx + suffix, WorkspaceID: workspaceID, Status: models.ConfigurationVersionStatusUploaded}
	}
	own, other := version("9160000", workspace.ID), version("9161111", otherWorkspace.ID)
	// Written directly: the shape of a run row stored before a run create checked its
	// configuration version.
	run := func(suffix string, configurationVersion *models.ConfigurationVersion) *models.Run {
		return &models.Run{
			ID: "run-" + sfx + suffix, WorkspaceID: workspace.ID, ConfigurationVersionID: &configurationVersion.ID,
			Status: models.RunStatusPending, Operation: models.RunOperationPlanOnly,
		}
	}
	ownRun, storedEarlier := run("9160000", own), run("9161111", other)
	for _, row := range []any{org, otherOrg, project, otherProject, workspace, otherWorkspace, own, other, ownRun, storedEarlier} {
		if err := db.Create(row).Error; err != nil {
			t.Fatalf("seeding %T: %v", row, err)
		}
	}
	t.Cleanup(func() {
		// Children before parents (foreign-key order), each statement scoped to this run's rows.
		db.Where("id IN ?", []string{ownRun.ID, storedEarlier.ID}).Delete(&models.Run{})
		db.Where("id IN ?", []string{own.ID, other.ID}).Delete(&models.ConfigurationVersion{})
		db.Where("id IN ?", []string{workspace.ID, otherWorkspace.ID}).Delete(&models.Workspace{})
		db.Where("id IN ?", []uuid.UUID{project.ID, otherProject.ID}).Delete(&models.Project{})
		db.Where("id IN ?", []uuid.UUID{org.ID, otherOrg.ID}).Delete(&models.Organization{})
	})

	// process runs one job to the point where it stops, and returns what storage was asked for.
	process := func(t *testing.T, run *models.Run) []string {
		t.Helper()
		job, err := json.Marshal(Job{RunID: run.ID, WorkspaceID: run.WorkspaceID, Operation: string(run.Operation)})
		if err != nil {
			t.Fatalf("marshalling the job: %v", err)
		}
		store := &recordingStorage{}
		err = processJob(t.Context(), job, nil,
			repository.NewWorkspaceRepository(db), repository.NewRunRepository(db), repository.NewConfigurationVersionRepository(db),
			nil, nil, store, nil, nil, nil, nil, nil, nil, nil, nil)
		if err == nil {
			t.Errorf("processJob succeeded with a storage client that holds nothing")
		}
		return store.asked
	}
	key := func(configurationVersion *models.ConfigurationVersion) string {
		return "configuration-versions/" + configurationVersion.ID + "/config.tar.gz"
	}

	t.Run("a run naming another workspace's configuration version downloads nothing", func(t *testing.T) {
		if asked := process(t, storedEarlier); len(asked) != 0 {
			t.Errorf("storage was asked for %v, want nothing downloaded", asked)
		}
		var failed models.Run
		if err := db.First(&failed, "id = ?", storedEarlier.ID).Error; err != nil {
			t.Fatalf("reloading the run: %v", err)
		}
		if failed.Status != models.RunStatusFailed {
			t.Errorf("the run is %q, want failed", failed.Status)
		}
	})
	t.Run("a run naming its workspace's configuration version downloads it", func(t *testing.T) {
		if asked := process(t, ownRun); !slices.Contains(asked, key(own)) {
			t.Errorf("storage was asked for %v, want the run's own configuration %s", asked, key(own))
		}
	})
}
