// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/michielvha/logger"
	"github.com/michielvha/stackweaver/core/crypto"
	"github.com/michielvha/stackweaver/core/models"
	"github.com/michielvha/stackweaver/core/plugins"
	"github.com/michielvha/stackweaver/core/plugins/opentofu"
	"github.com/michielvha/stackweaver/core/queue"
	"github.com/michielvha/stackweaver/core/repository"
	"github.com/michielvha/stackweaver/core/services/encryptionkey"
	"github.com/michielvha/stackweaver/core/services/logbuffer"
	"github.com/michielvha/stackweaver/core/services/logparser"
	"github.com/michielvha/stackweaver/core/services/oidc"
	"github.com/michielvha/stackweaver/core/services/state"
	"github.com/michielvha/stackweaver/core/services/variable"
	"github.com/michielvha/stackweaver/core/storage"
)

// getEnv returns the value of an environment variable or a fallback default.
func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

// getEnvInt returns the integer value of an environment variable or a fallback default.
func getEnvInt(key string, fallback int) int {
	if value, ok := os.LookupEnv(key); ok {
		if i, err := strconv.Atoi(value); err == nil {
			return i
		}
	}
	return fallback
}

type Job struct {
	RunID       string `json:"run_id"`
	WorkspaceID string `json:"workspace_id"`
	Operation   string `json:"operation"`
}

// createCancellableContext wraps a context with database polling to detect cancellation
// It polls the database every 2 seconds to check if the run has been cancelled
// If cancelled, it cancels the context which will kill the terraform process
// Returns the cancellable context and a cancel function
func createCancellableContext(ctx context.Context, runRepo *repository.RunRepository, runID string) (context.Context, context.CancelFunc) {
	cancelCtx, cancel := context.WithCancel(ctx) //nolint:gosec // G118: cancel is returned to caller who is responsible for calling it

	go func() {
		ticker := time.NewTicker(2 * time.Second) // Check every 2 seconds
		defer ticker.Stop()

		for {
			select {
			case <-cancelCtx.Done():
				// Context was cancelled (timeout or parent cancelled), stop polling
				return
			case <-ticker.C:
				// Poll database to check if run was cancelled
				run, err := runRepo.GetByID(runID)
				if err != nil {
					// If we can't read the run, log but continue polling
					logger.Warnf("Failed to check cancellation status for run %s: %v", runID, err)
					continue
				}
				if run.Status == models.RunStatusCancelled {
					logger.Infof("Run %s was cancelled, cancelling context to stop terraform process", runID)
					cancel() // Cancel the context, which will kill terraform process
					return
				}
			}
		}
	}()

	return cancelCtx, cancel
}

func main() {
	// Initialize logger first (reads LOG_LEVEL from environment)
	logLevel := os.Getenv("LOG_LEVEL")
	logger.Init(logLevel)

	// Check if running in agent mode (self-hosted runner)
	if os.Getenv("RUNNER_MODE") == "agent" {
		logger.Info("Starting OpenTofu runner in agent mode...")
		RunAgentMode()
		return
	}

	// Initialize dependencies (platform-hosted mode)
	redisQueue, err := queue.NewRedisQueue(
		getEnv("REDIS_HOST", "localhost"),
		getEnvInt("REDIS_PORT", 6379),
		os.Getenv("REDIS_PASSWORD"),
		getEnvInt("REDIS_DB", 0),
	)
	if err != nil {
		logger.Fatalf("Failed to connect to Redis: %v", err)
	}
	defer func() {
		if err := redisQueue.Close(); err != nil {
			logger.Warnf("Failed to close Redis queue: %v", err)
		}
	}()

	db, err := repository.NewDatabase(repository.Config{
		Host:            getEnv("DATABASE_HOST", "localhost"),
		Port:            getEnvInt("DATABASE_PORT", 5432),
		User:            getEnv("DATABASE_USER", "iac"),
		Password:        getEnv("DATABASE_PASSWORD", "iac_password"),
		DBName:          getEnv("DATABASE_NAME", "iac_platform"),
		SSLMode:         getEnv("DATABASE_SSLMODE", "disable"),
		MaxOpenConns:    10,
		MaxIdleConns:    5,
		ConnMaxLifetime: 5 * time.Minute,
	})
	if err != nil {
		// Close Redis queue before exiting
		if closeErr := redisQueue.Close(); closeErr != nil {
			logger.Warnf("Failed to close Redis queue before exit: %v", closeErr)
		}
		//nolint:gocritic // False positive: we explicitly close redisQueue before logger.Fatalf
		logger.Fatalf("Failed to connect to database: %v", err)
	}

	// Initialize unified storage client (single bucket for all data)
	storageCfg := storage.ConfigFromEnv()
	storageClient, err := storage.NewClient(context.Background(), storageCfg)
	if err != nil {
		logger.Fatalf("Failed to connect to storage: %v", err)
	}

	// Initialize Redis log buffer service (reuse Redis connection from queue)
	logBufferService := logbuffer.NewRedisLogBuffer(redisQueue.Client())

	// Initialize repositories and services
	workspaceRepo := repository.NewWorkspaceRepository(db)
	runRepo := repository.NewRunRepository(db)
	configVersionRepo := repository.NewConfigurationVersionRepository(db)
	phaseStateRepo := repository.NewRunPhaseStateRepository(db)
	taskStageRepo := repository.NewTaskStageRepository(db)
	stateVersionRepo := repository.NewStateVersionRepository(db)
	stateLockRepo := repository.NewStateLockRepository(db)
	stateOutputRepo := repository.NewStateVersionOutputRepository(db)
	stateResourceRepo := repository.NewStateVersionResourceRepository(db)
	varRepo := repository.NewVariableRepository(db)
	variableSetRepo := repository.NewVariableSetRepository(db)

	// Get encryption key for variables (match API handling). Fails loud on a
	// missing/insecure key (AUD-013); DEV_INSECURE_KEY=1 is the local-dev hatch.
	encryptionKey := encryptionkey.Resolve(os.Getenv("ENCRYPTION_KEY"))

	// Shared AES-256-GCM service for encryption at rest (#95): state objects written by
	// the embedded runner and sensitive output values encrypt under the same key the API
	// uses, so either binary can read the other's state. nil = plaintext (dev/legacy).
	var atRestCrypto *crypto.CryptoService
	if len(encryptionKey) > 0 {
		if cs, cErr := crypto.NewCryptoService(encryptionKey); cErr == nil {
			atRestCrypto = cs
		} else {
			logger.Warnf("Encryption at rest disabled: %v", cErr)
		}
	}

	stateMaterializer := state.NewMaterializer(stateOutputRepo, stateResourceRepo, atRestCrypto)
	stateService := state.NewService(stateVersionRepo, stateLockRepo, workspaceRepo, storageClient, stateMaterializer, atRestCrypto)

	variableService := variable.NewServiceWithVariableSetsAndWorkspace(varRepo, variableSetRepo, workspaceRepo, encryptionKey)

	// OIDC Workload Identity: Initialize signing key and token service for cloud OIDC (Azure, AWS)
	azureOIDCRepo := repository.NewAzureOIDCConfigurationRepository(db)
	awsOIDCRepo := repository.NewAWSOIDCConfigurationRepository(db)
	gcpOIDCRepo := repository.NewGCPOIDCConfigurationRepository(db)
	vaultOIDCRepo := repository.NewVaultOIDCConfigurationRepository(db)
	oidcSigningKey, oidcErr := oidc.NewSigningKey()
	var oidcTokenService *oidc.TokenService
	if oidcErr != nil {
		logger.Warnf("Failed to initialize OIDC signing key: %v (OIDC workload identity will be disabled)", oidcErr)
	} else {
		issuerURL := os.Getenv("OIDC_ISSUER_URL")
		if issuerURL == "" {
			issuerURL = os.Getenv("API_URL")
		}
		if issuerURL == "" {
			issuerURL = "http://localhost:8022"
		}
		oidcTokenService = oidc.NewTokenService(oidcSigningKey, issuerURL)
		logger.Info("OIDC workload identity token service initialized")
	}

	// Start worker
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// AUD-015: reliable consumption. A stable consumer ID (hostname) lets us recover any job this
	// consumer was mid-processing when it last crashed - RequeueProcessing moves leftover in-flight
	// messages from its processing list back onto the queue.
	consumerID, _ := os.Hostname()
	if consumerID == "" {
		consumerID = "terraform-runner"
	}
	if n, rErr := redisQueue.RequeueProcessing(context.Background(), "runs", consumerID); rErr != nil {
		logger.Warnf("Failed to recover in-flight runs from processing list: %v", rErr)
	} else if n > 0 {
		logger.Infof("Recovered %d in-flight run(s) from a previous crash", n)
	}

	go func() {
		logger.Info("Runner started, waiting for jobs...")
		for {
			select {
			case <-ctx.Done():
				return
			default:
				// AUD-015: BLMOVE the job to this consumer's processing list so a crash mid-run
				// doesn't lose it. Ack on completion; dead-letter a poison (unmarshalable) message.
				payload, err := redisQueue.DequeueReliable(ctx, "runs", consumerID, 5*time.Second)
				if err != nil {
					if err != queue.ErrQueueEmpty {
						logger.Errorf("Error dequeuing job: %v", err)
						time.Sleep(1 * time.Second)
					}
					continue
				}
				perr := processJob(ctx, payload, logBufferService, workspaceRepo, runRepo, configVersionRepo, phaseStateRepo, taskStageRepo, storageClient, stateService, variableService, azureOIDCRepo, awsOIDCRepo, gcpOIDCRepo, vaultOIDCRepo, oidcTokenService)
				if errors.Is(perr, errPoisonMessage) {
					logger.Errorf("Dead-lettering unprocessable job: %v", perr)
					if dErr := redisQueue.DeadLetter(context.Background(), "runs", consumerID, payload); dErr != nil { //nolint:contextcheck
						logger.Errorf("Failed to dead-letter job: %v", dErr)
					}
					continue
				}
				if perr != nil {
					logger.Errorf("Error processing job: %v", perr)
				}
				// The job's outcome is recorded in the DB (or it failed cleanly); ack it so it
				// leaves the processing list. A crash BEFORE this ack leaves it recoverable.
				if aErr := redisQueue.Ack(context.Background(), "runs", consumerID, payload); aErr != nil { //nolint:contextcheck
					logger.Errorf("Failed to ack job: %v", aErr)
				}
			}
		}
	}()

	// Wait for interrupt
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	logger.Info("Shutting down runner...")
	cancel()
}

// errPoisonMessage marks a queue message that can never be processed (e.g. an unmarshalable
// payload) so the consume loop dead-letters it instead of retrying it forever (AUD-015).
var errPoisonMessage = errors.New("unprocessable message")

func processJob(
	ctx context.Context,
	jobData []byte,
	logBufferService *logbuffer.RedisLogBuffer,
	workspaceRepo *repository.WorkspaceRepository,
	runRepo *repository.RunRepository,
	configVersionRepo *repository.ConfigurationVersionRepository,
	phaseStateRepo *repository.RunPhaseStateRepository,
	taskStageRepo *repository.TaskStageRepository,
	storageClient storage.Client,
	stateService *state.Service,
	variableService *variable.Service,
	azureOIDCRepo *repository.AzureOIDCConfigurationRepository,
	awsOIDCRepo *repository.AWSOIDCConfigurationRepository,
	gcpOIDCRepo *repository.GCPOIDCConfigurationRepository,
	vaultOIDCRepo *repository.VaultOIDCConfigurationRepository,
	oidcTokenService *oidc.TokenService,
) error {
	var job Job
	if err := json.Unmarshal(jobData, &job); err != nil {
		return fmt.Errorf("%w: failed to unmarshal job: %v", errPoisonMessage, err)
	}

	logger.Infof("Processing job: RunID=%s, WorkspaceID=%s, Operation=%s", job.RunID, job.WorkspaceID, job.Operation)

	// Get run
	run, err := runRepo.GetByID(job.RunID)
	if err != nil {
		return fmt.Errorf("failed to get run: %w", err)
	}

	// Only pending/planning/applying runs are executable. Any other status means this message is
	// stale - a duplicate, or one reclaimed (AUD-015) after its run already finished - so skip it
	// as a safe no-op instead of resurrecting a terminal run.
	switch run.Status { //nolint:exhaustive // only pending/pre_plan_completed/planning/applying are executable; all others skip via default
	case models.RunStatusPending, models.RunStatusPrePlanCompleted, models.RunStatusPlanning, models.RunStatusApplying:
		// executable (pre_plan_completed = a run whose pre_plan task stage passed, dispatchable like pending)
	default:
		logger.Infof("Run %s is in non-executable state %s, skipping (stale/reclaimed message)", run.ID, run.Status)
		return nil
	}

	// Update run status based on operation and current phase
	now := time.Now()

	// Determine appropriate status based on run operation and current phase
	switch run.Operation {
	case models.RunOperationPlanAndApply:
		// Plan-and-apply run: Check current phase
		if run.Status == models.RunStatusPending || run.Status == models.RunStatusPrePlanCompleted {
			// Starting plan phase
			run.Status = models.RunStatusPlanning
		}
		// Note: If status is already RunStatusApplying, we keep it as is
	case models.RunOperationPlanOnly:
		// Plan-only run: Set to planning
		if run.Status == models.RunStatusPending || run.Status == models.RunStatusPrePlanCompleted {
			run.Status = models.RunStatusPlanning
		}
	case models.RunOperationDestroy:
		// Destroy run: Set to planning (destroy uses plan phase)
		if run.Status == models.RunStatusPending || run.Status == models.RunStatusPrePlanCompleted {
			run.Status = models.RunStatusPlanning
		}
	default:
		// Unknown operation type - log warning and set to planning as fallback
		logger.Warnf("Unknown run operation type %s for run %s, defaulting to planning status", run.Operation, run.ID)
		if run.Status == models.RunStatusPending || run.Status == models.RunStatusPrePlanCompleted {
			run.Status = models.RunStatusPlanning
		}
	}

	// Set started time if not already set
	if run.StartedAt == nil {
		run.StartedAt = &now
	}
	if _, err := runRepo.CompleteIfNotCanceled(run); err != nil {
		return fmt.Errorf("failed to update run: %w", err)
	}

	// Get workspace
	workspace, err := workspaceRepo.GetByID(job.WorkspaceID)
	if err != nil {
		return fmt.Errorf("failed to get workspace: %w", err)
	}

	// Check if workspace is manually locked (TFE-compatible)
	if workspace.Locked {
		run.Status = models.RunStatusFailed
		reason := "Workspace is manually locked. Unlock the workspace to allow runs."
		if workspace.LockedReason != "" {
			reason = fmt.Sprintf("Workspace is manually locked: %s", workspace.LockedReason)
		}
		run.ErrorMessage = reason
		now := time.Now()
		run.CompletedAt = &now
		if _, err := runRepo.CompleteIfNotCanceled(run); err != nil {
			logger.Warnf("Failed to update run status: %v", err)
		}
		return fmt.Errorf("workspace is manually locked")
	}

	// Acquire state lock for apply/destroy operations (TFE-compatible)
	// Use defer to ensure lock is released even if function returns early
	var lockID string
	if run.Operation == models.RunOperationPlanAndApply || run.Operation == models.RunOperationDestroy {
		lockID = fmt.Sprintf("run-%s", run.ID)
		ttl := time.Duration(workspace.RunTimeout) * time.Second
		if ttl == 0 {
			ttl = 2 * time.Hour // Default TTL
		}

		// Try to acquire lock
		if err := stateService.LockState(ctx, job.WorkspaceID, lockID, string(run.Operation), &run.ID, ttl); err != nil {
			// Check if lock exists and is not expired
			existingLock, lockErr := stateService.GetStateLock(ctx, job.WorkspaceID)
			if lockErr == nil && existingLock != nil && !existingLock.IsExpired() {
				run.Status = models.RunStatusFailed
				run.ErrorMessage = fmt.Sprintf("State is locked by another operation (lock ID: %s)", existingLock.LockID)
				now := time.Now()
				run.CompletedAt = &now
				if _, updateErr := runRepo.CompleteIfNotCanceled(run); updateErr != nil {
					logger.Warnf("Failed to update run status: %v", updateErr)
				}
				lockedByStr := "unknown"
				if existingLock.LockedBy != nil {
					lockedByStr = *existingLock.LockedBy
				}
				return fmt.Errorf("failed to acquire state lock: state is locked by run %s", lockedByStr)
			}
			// If expired or doesn't exist, try again
			if retryErr := stateService.LockState(ctx, job.WorkspaceID, lockID, string(run.Operation), &run.ID, ttl); retryErr != nil {
				run.Status = models.RunStatusFailed
				run.ErrorMessage = fmt.Sprintf("Failed to acquire state lock: %s", retryErr.Error())
				now := time.Now()
				run.CompletedAt = &now
				if _, updateErr := runRepo.CompleteIfNotCanceled(run); updateErr != nil {
					logger.Warnf("Failed to update run status: %v", updateErr)
				}
				return fmt.Errorf("failed to acquire state lock: %w", retryErr)
			}
		}
		logger.Infof("State lock acquired for run %s (lock ID: %s)", run.ID, lockID)

		// Defer lock release to ensure cleanup
		defer func() {
			if unlockErr := stateService.UnlockState(ctx, job.WorkspaceID, lockID); unlockErr != nil {
				logger.Warnf("Failed to release state lock for run %s: %v", run.ID, unlockErr)
			} else {
				logger.Infof("State lock released for run %s", run.ID)
			}
		}()
	}

	// Create workspace directory
	// Use /home/iac/workspaces for non-root user compatibility
	workspaceDir := fmt.Sprintf("/home/iac/workspaces/%s", workspace.ID)
	// AUD-026: wipe the per-workspace dir before extracting this run's configuration. The path is
	// stable (keyed on workspace ID) and reused across runs; without a clean, files deleted in the
	// new commit (e.g. a removed .tf) survived from the previous run and got applied, and stale
	// tfvars/plan files lingered. RemoveAll + MkdirAll gives each run a clean checkout (agent mode
	// already does this via MkdirTemp; this is the platform-runner twin).
	if err := os.RemoveAll(workspaceDir); err != nil {
		return fmt.Errorf("failed to clean workspace directory: %w", err)
	}
	if err := os.MkdirAll(workspaceDir, 0o755); err != nil { //nolint:gosec // workspace directories need 0o755 for compatibility
		return fmt.Errorf("failed to create workspace directory: %w", err)
	}

	// TFE-compatible: Download configuration files from storage if configuration version exists
	// This is the primary method - configuration files are uploaded via PUT /api/v2/configuration-versions/:id/upload
	var configVersion *models.ConfigurationVersion
	if run.ConfigurationVersionID != nil {
		var err error
		configVersion, err = configVersionRepo.GetByID(*run.ConfigurationVersionID)
		if err != nil {
			run.Status = models.RunStatusFailed
			run.ErrorMessage = fmt.Sprintf("Failed to get configuration version: %v", err)
			run.CompletedAt = &now
			if _, err := runRepo.CompleteIfNotCanceled(run); err != nil {
				logger.Warnf("Failed to update run status: %v", err)
			}
			return fmt.Errorf("failed to get configuration version: %w", err)
		}

		// Check if configuration version is uploaded
		if configVersion.Status != models.ConfigurationVersionStatusUploaded {
			run.Status = models.RunStatusFailed
			run.ErrorMessage = fmt.Sprintf("Configuration version not uploaded (status: %s)", configVersion.Status)
			run.CompletedAt = &now
			if _, err := runRepo.CompleteIfNotCanceled(run); err != nil {
				logger.Warnf("Failed to update run status: %v", err)
			}
			return fmt.Errorf("configuration version not uploaded")
		}

		// Download configuration files from storage
		// Path: configuration-versions/{config_version_id}/config.tar.gz
		configStorageKey := fmt.Sprintf("configuration-versions/%s/config.tar.gz", configVersion.ID)
		logger.Infof("Downloading configuration from storage: %s", configStorageKey)

		configData, err := storageClient.Get(ctx, configStorageKey)
		if err != nil {
			run.Status = models.RunStatusFailed
			run.ErrorMessage = fmt.Sprintf("Failed to download configuration files: %v", err)
			run.CompletedAt = &now
			if _, err := runRepo.CompleteIfNotCanceled(run); err != nil {
				logger.Warnf("Failed to update run status: %v", err)
			}
			return fmt.Errorf("failed to download configuration files: %w", err)
		}

		// Extract tar.gz to workspace directory
		logger.Infof("Extracting configuration files to %s", workspaceDir)
		if err := extractTarGz(configData, workspaceDir); err != nil {
			run.Status = models.RunStatusFailed
			run.ErrorMessage = fmt.Sprintf("Failed to extract configuration files: %v", err)
			run.CompletedAt = &now
			if _, err := runRepo.CompleteIfNotCanceled(run); err != nil {
				logger.Warnf("Failed to update run status: %v", err)
			}
			return fmt.Errorf("failed to extract configuration files: %w", err)
		}
		logger.Infof("Configuration files extracted successfully")

	} else {
		// Fallback: If no configuration version, allow the run to proceed
		// This is for backward compatibility and manual runs from the UI
		// TFE primarily uses configuration versions, but we allow manual runs without them
		logger.Warn("Run has no configuration version, proceeding without configuration files")
		// Note: The workspace directory will be empty, which is fine for manual runs
		// where configuration might be provided via other means or the workspace might
		// be configured to use VCS directly
	}

	// Handle working directory (TFE-compatible)
	// If workspace has a working directory specified, use that subdirectory
	terraformDir := workspaceDir
	if workspace.WorkingDirectory != "" && workspace.WorkingDirectory != "." && workspace.WorkingDirectory != "/" {
		// For VCS-triggered runs, tarball contains full repository structure from root
		// For manual uploads, tarball may contain only the working directory
		if workspace.VCSConnectionID != nil && workspace.VCSRepository != "" {
			// VCS-triggered: tarball contains full repo structure, working directory is a subdirectory
			terraformDir = filepath.Join(workspaceDir, strings.TrimPrefix(workspace.WorkingDirectory, "/"))
			logger.Infof("Using working directory (VCS-triggered, full repo structure): %s", terraformDir)
		} else {
			// Manual upload: append working directory to find files
			terraformDir = filepath.Join(workspaceDir, strings.TrimPrefix(workspace.WorkingDirectory, "/"))
			logger.Infof("Using working directory: %s", terraformDir)
		}

		// AUD-074: reject a working directory that escapes the workspace root (e.g. "../../etc").
		// filepath.Join already cleans the path, so a containment check on the result is sufficient.
		if terraformDir != workspaceDir && !strings.HasPrefix(terraformDir, workspaceDir+string(os.PathSeparator)) {
			run.Status = models.RunStatusFailed
			run.ErrorMessage = fmt.Sprintf("Invalid working directory (escapes workspace root): %s", workspace.WorkingDirectory)
			run.CompletedAt = &now
			if _, err := runRepo.CompleteIfNotCanceled(run); err != nil {
				logger.Warnf("Failed to update run status: %v", err)
			}
			return fmt.Errorf("invalid working directory (escapes workspace root): %s", workspace.WorkingDirectory)
		}

		// Verify working directory exists
		if _, err := os.Stat(terraformDir); os.IsNotExist(err) {
			run.Status = models.RunStatusFailed
			run.ErrorMessage = fmt.Sprintf("Working directory not found: %s (resolved to: %s)", workspace.WorkingDirectory, terraformDir)
			run.CompletedAt = &now
			if _, err := runRepo.CompleteIfNotCanceled(run); err != nil {
				logger.Warnf("Failed to update run status: %v", err)
			}
			return fmt.Errorf("working directory not found: %s (resolved to: %s)", workspace.WorkingDirectory, terraformDir)
		}
	}

	// TFE-compatible: Replace remote backend with local backend for runner execution
	// When runs are executed remotely, the backend should use local state or state service
	// This prevents the runner from creating nested runs (infinite loop)
	// IMPORTANT: Do this BEFORE init, so init uses the correct backend
	if err := replaceRemoteBackendWithLocal(terraformDir); err != nil {
		logger.Warnf("Failed to replace remote backend: %v (continuing anyway)", err)
	}

	// AUD-149: restore the workspace's current state before running terraform. The remote runner uses
	// a local backend (terraform.tfstate) in a workspace dir that is wiped for a clean checkout each
	// job, so without this every run starts from EMPTY state - a destroy would find nothing to destroy
	// and a second apply would try to recreate everything. The agent runner already does this
	// (agent_mode.go); the platform runner was missing it. No-op on a fresh workspace with no state.
	if latest, lerr := stateService.GetLatestState(ctx, job.WorkspaceID); lerr == nil && latest != nil {
		if stateData, gerr := stateService.GetStateObject(ctx, job.WorkspaceID, latest.Version); gerr == nil && len(stateData) > 0 {
			stateFile := filepath.Join(terraformDir, "terraform.tfstate")
			if werr := os.WriteFile(stateFile, stateData, 0o600); werr != nil { //nolint:gosec // G703: stateFile is the validated workspace dir + a constant filename
				logger.Warnf("Failed to restore state file for run %s: %v", run.ID, werr)
			} else {
				logger.Infof("Restored state for run %s (%d bytes, version %d)", run.ID, len(stateData), latest.Version)
			}
		}
	}

	// Get terraform variables (category == "terraform") - these go in stackweaver.auto.tfvars
	variablesMeta, err := variableService.GetVariablesWithMetaForRun(ctx, workspace.ID)
	if err != nil {
		// Update run status to failed if variable retrieval fails
		run.Status = models.RunStatusFailed
		run.ErrorMessage = fmt.Sprintf("Failed to get variables: %v", err)
		run.CompletedAt = &now
		if _, updateErr := runRepo.CompleteIfNotCanceled(run); updateErr != nil {
			logger.Warnf("Failed to update run status: %v", updateErr)
		}
		return fmt.Errorf("failed to get variables: %w", err)
	}
	// Convert to the plugin's HCL-aware variable type so HCL-typed variables are written
	// unquoted in tfvars (AUD-022).
	variables := make(map[string]plugins.TFVar, len(variablesMeta))
	for k, v := range variablesMeta {
		variables[k] = plugins.TFVar{Value: v.Value, HCL: v.HCL}
	}

	// Get environment variables (category == "env") - these are set as actual environment variables
	// TFE-compatible: Environment variables are not included in stackweaver.auto.tfvars
	envVars, err := variableService.GetEnvironmentVariablesForRun(ctx, workspace.ID)
	if err != nil {
		return fmt.Errorf("failed to get environment variables: %w", err)
	}

	// OIDC Workload Identity: If Azure OIDC configurations exist for this organization,
	// generate a signed JWT and inject environment variables for Azure authentication.
	// This enables keyless authentication from Terraform runs to Azure.
	if azureOIDCRepo != nil && oidcTokenService != nil {
		orgID := workspace.Project.OrganizationID
		configs, oidcErr := azureOIDCRepo.GetByOrganization(orgID)
		if oidcErr != nil {
			logger.Warnf("Failed to look up Azure OIDC configurations for org %s: %v", orgID, oidcErr)
		} else if len(configs) > 0 {
			// Use the first OIDC configuration (an org typically has one Azure OIDC config)
			config := configs[0]

			// Determine the run phase
			runPhase := "plan"
			if run.Status == models.RunStatusApplying {
				runPhase = "apply"
			}

			orgName := workspace.Project.Organization.Name
			projectName := workspace.Project.Name

			// Generate OIDC token with audience set to the Azure client ID
			// TFC-compatible: the audience is "api://AzureADTokenExchange" by default,
			// but we use the client ID which is what Azure federated credentials expect
			token, tokenErr := oidcTokenService.GenerateToken(oidc.TokenRequest{
				Audience:         "api://AzureADTokenExchange",
				OrganizationName: orgName,
				OrganizationID:   workspace.Project.OrganizationID.String(),
				ProjectName:      projectName,
				ProjectID:        workspace.Project.ID.String(),
				WorkspaceName:    workspace.Name,
				WorkspaceID:      workspace.ID,
				RunID:            run.ID,
				RunPhase:         runPhase,
			})
			if tokenErr != nil {
				logger.Warnf("Failed to generate OIDC token for run %s: %v", run.ID, tokenErr)
			} else {
				// Inject TFC-compatible workload identity env vars
				envVars["TFC_WORKLOAD_IDENTITY_TOKEN"] = token

				// Inject Azure-specific env vars for the AzureRM/AzAPI Terraform providers
				envVars["ARM_OIDC_TOKEN"] = token
				envVars["ARM_CLIENT_ID"] = config.ClientID
				envVars["ARM_SUBSCRIPTION_ID"] = config.SubscriptionID
				envVars["ARM_TENANT_ID"] = config.TenantID
				envVars["ARM_USE_OIDC"] = "true"

				logger.Infof("Injected OIDC workload identity token for run %s (org=%s, workspace=%s)", run.ID, orgName, workspace.Name)
			}
		}
	}

	// OIDC Workload Identity: inject AWS keyless-auth env for Terraform runs when an AWS OIDC
	// configuration exists for this organization. Mirrors the Azure block above, but AWS reads the
	// token from a file (AWS_WEB_IDENTITY_TOKEN_FILE) rather than an env value, so the runner writes
	// the token into the run's working directory. Enables keyless AssumeRoleWithWebIdentity.
	if awsOIDCRepo != nil && oidcTokenService != nil {
		orgID := workspace.Project.OrganizationID
		configs, oidcErr := awsOIDCRepo.GetByOrganization(orgID)
		if oidcErr != nil {
			logger.Warnf("Failed to look up AWS OIDC configurations for org %s: %v", orgID, oidcErr)
		} else if len(configs) > 0 {
			// An org typically has one AWS OIDC config.
			awsConfig := configs[0]

			runPhase := "plan"
			if run.Status == models.RunStatusApplying {
				runPhase = "apply"
			}
			orgName := workspace.Project.Organization.Name

			// Audience "sts.amazonaws.com" is what AWS STS AssumeRoleWithWebIdentity expects.
			token, tokenErr := oidcTokenService.GenerateToken(oidc.TokenRequest{
				Audience:         "sts.amazonaws.com",
				OrganizationName: orgName,
				OrganizationID:   workspace.Project.OrganizationID.String(),
				ProjectName:      workspace.Project.Name,
				ProjectID:        workspace.Project.ID.String(),
				WorkspaceName:    workspace.Name,
				WorkspaceID:      workspace.ID,
				RunID:            run.ID,
				RunPhase:         runPhase,
			})
			if tokenErr != nil {
				logger.Warnf("Failed to generate AWS OIDC token for run %s: %v", run.ID, tokenErr)
			} else {
				sessionName := fmt.Sprintf("stackweaver-%s", run.ID)
				awsEnv, envErr := buildAWSOIDCEnv(awsConfig.RoleARN, token, terraformDir, sessionName)
				if envErr != nil {
					logger.Warnf("Failed to build AWS OIDC env for run %s: %v", run.ID, envErr)
				} else {
					for k, v := range awsEnv {
						envVars[k] = v
					}
					logger.Infof("Injected AWS OIDC workload identity for run %s (org=%s, workspace=%s, role=%s)", run.ID, orgName, workspace.Name, awsConfig.RoleARN)
				}
			}
		}
	}

	// OIDC Workload Identity: inject GCP keyless-auth env for Terraform runs when a GCP OIDC
	// configuration exists for this organization. Mirrors the AWS block, but GCP reads an
	// external-account credential-config JSON (GOOGLE_APPLICATION_CREDENTIALS) that references a token
	// file, so the runner writes both files into the run's working directory. Enables Workload Identity
	// Federation with no static credentials.
	if gcpOIDCRepo != nil && oidcTokenService != nil {
		orgID := workspace.Project.OrganizationID
		configs, oidcErr := gcpOIDCRepo.GetByOrganization(orgID)
		if oidcErr != nil {
			logger.Warnf("Failed to look up GCP OIDC configurations for org %s: %v", orgID, oidcErr)
		} else if len(configs) > 0 {
			// An org typically has one GCP OIDC config.
			gcpConfig := configs[0]

			runPhase := "plan"
			if run.Status == models.RunStatusApplying {
				runPhase = "apply"
			}
			orgName := workspace.Project.Organization.Name

			// WIF audience is the full provider resource name prefixed with //iam.googleapis.com/.
			token, tokenErr := oidcTokenService.GenerateToken(oidc.TokenRequest{
				Audience:         "//iam.googleapis.com/" + gcpConfig.WorkloadProviderName,
				OrganizationName: orgName,
				OrganizationID:   workspace.Project.OrganizationID.String(),
				ProjectName:      workspace.Project.Name,
				ProjectID:        workspace.Project.ID.String(),
				WorkspaceName:    workspace.Name,
				WorkspaceID:      workspace.ID,
				RunID:            run.ID,
				RunPhase:         runPhase,
			})
			if tokenErr != nil {
				logger.Warnf("Failed to generate GCP OIDC token for run %s: %v", run.ID, tokenErr)
			} else {
				gcpEnv, envErr := buildGCPOIDCEnv(gcpConfig.ServiceAccountEmail, gcpConfig.ProjectNumber, gcpConfig.WorkloadProviderName, token, terraformDir)
				if envErr != nil {
					logger.Warnf("Failed to build GCP OIDC env for run %s: %v", run.ID, envErr)
				} else {
					for k, v := range gcpEnv {
						envVars[k] = v
					}
					logger.Infof("Injected GCP OIDC workload identity for run %s (org=%s, workspace=%s, sa=%s)", run.ID, orgName, workspace.Name, gcpConfig.ServiceAccountEmail)
				}
			}
		}
	}

	// OIDC Workload Identity: inject Vault keyless-auth env for Terraform runs when a Vault OIDC
	// configuration exists for this organization. Unlike the cloud providers, Vault needs an active
	// login: the runner exchanges the minted JWT for a Vault token (JWT auth method) and exports
	// VAULT_ADDR + VAULT_TOKEN so the run's vault provider works with no auth block.
	if vaultOIDCRepo != nil && oidcTokenService != nil {
		orgID := workspace.Project.OrganizationID
		configs, oidcErr := vaultOIDCRepo.GetByOrganization(orgID)
		if oidcErr != nil {
			logger.Warnf("Failed to look up Vault OIDC configurations for org %s: %v", orgID, oidcErr)
		} else if len(configs) > 0 {
			// An org typically has one Vault OIDC config.
			vaultConfig := configs[0]

			runPhase := "plan"
			if run.Status == models.RunStatusApplying {
				runPhase = "apply"
			}
			orgName := workspace.Project.Organization.Name

			// Vault JWT auth validates the token's aud against the role's bound_audiences.
			token, tokenErr := oidcTokenService.GenerateToken(oidc.TokenRequest{
				Audience:         oidc.VaultWorkloadIdentityAudience,
				OrganizationName: orgName,
				OrganizationID:   workspace.Project.OrganizationID.String(),
				ProjectName:      workspace.Project.Name,
				ProjectID:        workspace.Project.ID.String(),
				WorkspaceName:    workspace.Name,
				WorkspaceID:      workspace.ID,
				RunID:            run.ID,
				RunPhase:         runPhase,
			})
			if tokenErr != nil {
				logger.Warnf("Failed to generate Vault OIDC token for run %s: %v", run.ID, tokenErr)
			} else {
				vaultEnv, envErr := buildVaultOIDCEnv(ctx, vaultConfig.Address, vaultConfig.RoleName, vaultConfig.Namespace, vaultConfig.JWTAuthPath, vaultConfig.TLSCACertificate, token, terraformDir)
				if envErr != nil {
					logger.Warnf("Failed to build Vault OIDC env for run %s (Vault login): %v", run.ID, envErr)
				} else {
					for k, v := range vaultEnv {
						envVars[k] = v
					}
					logger.Infof("Injected Vault OIDC workload identity for run %s (org=%s, workspace=%s, addr=%s)", run.ID, orgName, workspace.Name, vaultConfig.Address)
				}
			}
		}
	}

	// Resolve terraform version: workspace -> org default
	tofuVersion := workspace.TofuVersion
	if tofuVersion == "" {
		tofuVersion = workspace.Project.Organization.DefaultTofuVersion
	}
	if tofuVersion == "" {
		run.Status = models.RunStatusFailed
		run.ErrorMessage = "No OpenTofu version configured. Set a version on the workspace or set an organization default in Settings > OpenTofu Versions."
		now := time.Now()
		run.CompletedAt = &now
		if _, err := runRepo.CompleteIfNotCanceled(run); err != nil {
			logger.Warnf("Failed to update run status: %v", err)
		}
		return fmt.Errorf("no opentofu version configured for workspace %s", workspace.Name)
	}
	logger.Infof("Using OpenTofu version %s for workspace %s", tofuVersion, workspace.Name)

	// Initialize Terraform plugin (may download binary if not cached locally)
	plugin := opentofu.NewPlugin(tofuVersion) //nolint:contextcheck // download happens once at init, not per-request

	// Helper function to store logs to storage (for long-term persistence)
	// Logs should already be in Redis (streamed during execution), this copies them to storage
	storeLogs := func(logs string, phase string) {
		var logsKey string
		if run.Operation == models.RunOperationPlanAndApply {
			// For plan-and-apply runs, use phase-specific keys: plan.log or apply.log
			logsKey = fmt.Sprintf("runs/%s/logs/%s.log", run.ID, phase)
		} else {
			// For other runs, use operation name
			logsKey = fmt.Sprintf("runs/%s/logs/%s.log", run.ID, job.Operation)
		}
		if err := storageClient.Put(ctx, logsKey, []byte(logs)); err != nil {
			logger.Warnf("Failed to store logs to storage for run %s: %v", run.ID, err)
		}
	}

	// Helper function to copy logs from Redis to storage (called after completion)
	copyLogsFromRedisToStorage := func(phase string) {
		if err := logBufferService.CopyToStorage(ctx, run.ID, phase, storageClient); err != nil {
			logger.Warnf("Failed to copy logs from Redis to storage for run %s phase %s: %v", run.ID, phase, err)
		}
	}

	// Helper function to store parsed phase state in database
	storePhaseState := func(phase string) {
		// Get logs from storage
		logsKey := fmt.Sprintf("runs/%s/logs/%s.log", run.ID, phase)
		logsBytes, err := storageClient.Get(ctx, logsKey)
		if err != nil {
			logger.Warnf("Failed to get logs from storage for run %s phase %s: %v", run.ID, phase, err)
			return
		}
		logs := string(logsBytes)

		// For apply phase, extract planned resources from plan output
		var plannedResources []logparser.PlannedResource
		if phase == "apply" && run.PlanOutput != nil {
			plannedResources = logparser.ExtractPlannedResourcesFromPlanOutput(map[string]interface{}(run.PlanOutput))
		}

		// Parse logs
		parseResult, err := logparser.ParseApplyLogs(logs, plannedResources)
		if err != nil {
			logger.Warnf("Failed to parse logs for run %s phase %s: %v", run.ID, phase, err)
			return
		}

		// Store phase state
		phaseState := &models.RunPhaseState{
			RunID:     run.ID,
			Phase:     phase,
			Resources: parseResult.Resources,
			Summary:   parseResult.Summary,
			ParsedAt:  time.Now(),
		}

		if err := phaseStateRepo.Upsert(phaseState); err != nil {
			logger.Warnf("Failed to store phase state for run %s phase %s: %v", run.ID, phase, err)
		} else {
			logger.Infof("Stored phase state for run %s phase %s (%d resources)", run.ID, phase, len(parseResult.Resources))
		}
	}

	// TFE-compatible: Initialize Terraform (after backend replacement)
	// This ensures providers are downloaded and backend is configured correctly
	// Add timeout for init to prevent hanging (15 minutes should be enough for provider downloads)
	initTimeout := 15 * time.Minute
	initCtx, initCancel := context.WithTimeout(ctx, initTimeout)
	defer initCancel()

	logger.Infof("Starting terraform init for run %s (operation: %s)", run.ID, run.Operation)
	initResult, err := plugin.Init(initCtx, terraformDir, nil, envVars)
	if err != nil {
		// Store init logs even on failure
		if initResult != nil {
			storeLogs(initResult.Logs, "init")
		}
		// Check if timeout was exceeded
		if initCtx.Err() == context.DeadlineExceeded {
			run.Status = models.RunStatusFailed
			run.ErrorMessage = fmt.Sprintf("Terraform init exceeded timeout of %v", initTimeout)
		} else {
			run.Status = models.RunStatusFailed
			run.ErrorMessage = fmt.Sprintf("Terraform init failed: %v", err)
		}
		run.CompletedAt = &now
		if _, updateErr := runRepo.CompleteIfNotCanceled(run); updateErr != nil {
			logger.Warnf("Failed to update run status: %v", updateErr)
		}
		return err
	}
	// Store init logs
	if initResult != nil {
		storeLogs(initResult.Logs, "init")
	}
	logger.Infof("Terraform init completed successfully for run %s", run.ID)

	// Check if run was cancelled after init
	run, err = runRepo.GetByID(job.RunID)
	if err != nil {
		return fmt.Errorf("failed to reload run: %w", err)
	}
	if run.Status == models.RunStatusCancelled {
		logger.Infof("Run %s was cancelled after init, stopping execution", run.ID)
		return nil
	}

	// Execute operation and collect logs
	var operationLogs strings.Builder
	if initResult != nil {
		operationLogs.WriteString("=== Terraform Init ===\n")
		operationLogs.WriteString(initResult.Logs)
		operationLogs.WriteString("\n\n")
	}

	// Determine what phase to execute based on run operation and status
	// For plan-and-apply runs, check if we're in plan phase or apply phase
	executePlan := false
	executeApply := false

	switch run.Operation {
	case models.RunOperationPlanAndApply:
		// Plan-and-apply run: Check current phase
		switch run.Status {
		case models.RunStatusPlanning, models.RunStatusPending, models.RunStatusPrePlanCompleted:
			// Execute plan phase
			executePlan = true
		case models.RunStatusApplying:
			// Execute apply phase
			executeApply = true
		case models.RunStatusPlanned, models.RunStatusApplied, models.RunStatusFailed, models.RunStatusCancelled, models.RunStatusRunning, models.RunStatusCompleted,
			models.RunStatusPrePlanRunning, models.RunStatusPostPlanRunning, models.RunStatusPostPlanCompleted,
			models.RunStatusPreApplyRunning, models.RunStatusPreApplyCompleted, models.RunStatusPostApplyRunning, models.RunStatusPostApplyCompleted:
			// These statuses don't trigger execution - run is already in progress, completed, or
			// waiting on run-task stages (never executable from a queue message).
		}
	case models.RunOperationPlanOnly:
		// Plan-only run: Always execute plan
		executePlan = true
	case models.RunOperationDestroy:
		// TFE-compatible: Destroy runs follow the same two-phase flow as plan-and-apply
		// Phase 1: terraform plan -destroy (shows what will be destroyed)
		// Phase 2: terraform apply plan.out (actually destroys resources)
		switch run.Status { //nolint:exhaustive // only pending/planning/applying trigger execution
		case models.RunStatusPlanning, models.RunStatusPending, models.RunStatusPrePlanCompleted:
			executePlan = true
		case models.RunStatusApplying:
			executeApply = true
		}
	}

	// Finalize the streamed log for whichever phase this invocation runs: append the
	// ETX end-of-text marker (once, idempotently) and archive the framed buffer to
	// object storage. A defer guarantees this runs on every exit path - success,
	// failure, timeout, or cancellation - and only after all appends (including the
	// provider-error retry) are done, so ETX always lands at the true end of the stream.
	// Each invocation runs exactly one phase (executePlan/executeApply are derived from
	// run.Status and are mutually exclusive).
	defer func() { //nolint:contextcheck // must run on a fresh context even when the request ctx is cancelled/timed out
		phase := ""
		switch {
		case executePlan:
			phase = "plan"
		case executeApply:
			phase = "apply"
		default:
			return
		}
		// Use a fresh background context: a cancelled or timed-out run still needs its
		// log framed (ETX) and archived. Reusing the request ctx would fail both here
		// and in CopyToStorage exactly when finalization matters most.
		finalizeCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if finErr := logBufferService.Finalize(finalizeCtx, run.ID, phase); finErr != nil {
			logger.Warnf("Failed to finalize log stream for run %s phase %s: %v", run.ID, phase, finErr)
		}
		if copyErr := logBufferService.CopyToStorage(finalizeCtx, run.ID, phase, storageClient); copyErr != nil {
			logger.Warnf("Failed to archive finalized log for run %s phase %s: %v", run.ID, phase, copyErr)
		}
	}()

	// AUD-148: the plan and apply phases run as separate jobs, and each job wipes the workspace dir
	// for a clean checkout - so the plan.out the plan phase saved is gone by the time the apply job
	// runs `terraform apply plan.out`. Persist the saved plan across the phase boundary through object
	// storage so the apply phase runs the exact plan that was reviewed (TFE semantics), not a re-plan.
	planFileKey := fmt.Sprintf("runs/%s/plan.out", run.ID)
	persistPlanFile := func() {
		data, err := os.ReadFile(filepath.Join(terraformDir, "plan.out")) //nolint:gosec // plan.out is inside the run's own workspace dir
		if err != nil {
			logger.Warnf("Could not read plan file to persist for run %s: %v", run.ID, err)
			return
		}
		if err := storageClient.Put(ctx, planFileKey, data); err != nil {
			logger.Warnf("Failed to persist plan file for run %s: %v", run.ID, err)
			return
		}
		logger.Infof("Persisted plan file for run %s (%d bytes)", run.ID, len(data))
	}
	restorePlanFile := func() error {
		data, err := storageClient.Get(ctx, planFileKey)
		if err != nil {
			return fmt.Errorf("failed to fetch saved plan for run %s: %w", run.ID, err)
		}
		return os.WriteFile(filepath.Join(terraformDir, "plan.out"), data, 0o600)
	}

	// Execute plan phase
	if executePlan {
		// Create timeout context for plan operation based on workspace timeout
		// Use half of apply timeout for plan, or minimum 30 minutes
		planTimeout := time.Duration(workspace.RunTimeout) * time.Second / 2
		if planTimeout <= 0 {
			planTimeout = 30 * time.Minute // Default 30 minutes for plan
		} else if planTimeout < 30*time.Minute {
			planTimeout = 30 * time.Minute // Minimum 30 minutes
		}
		planCtx, planCancel := context.WithTimeout(ctx, planTimeout)
		defer planCancel()

		// Wrap with cancellation polling to detect cancellation during execution
		cancellablePlanCtx, cancelPolling := createCancellableContext(planCtx, runRepo, run.ID)
		defer cancelPolling()

		logger.Infof("Starting plan operation with timeout of %v for run %s", planTimeout, run.ID)

		// Use streaming Plan with callback to write logs to Redis
		// For destroy runs, add -destroy flag to plan (TFE-compatible two-phase destroy)
		planOptions := &opentofu.PlanOptions{
			OnOutputLine: func(line string) {
				if err := logBufferService.Append(cancellablePlanCtx, run.ID, "plan", line); err != nil {
					logger.Warnf("Failed to append plan log line to Redis: %v", err)
				}
			},
			Destroy: run.Operation == models.RunOperationDestroy,
		}
		planResult, err := plugin.PlanWithOptions(cancellablePlanCtx, terraformDir, variables, envVars, planOptions)
		if planResult != nil {
			operationLogs.WriteString("=== Terraform Plan ===\n")
			operationLogs.WriteString(planResult.Logs)
		}
		// ALWAYS copy logs from Redis to storage, even if cancelled
		// Logs are already in Redis from streaming callback, even if planResult is nil
		copyLogsFromRedisToStorage("plan")
		// Check if run was cancelled during plan
		run = reloadRun(runRepo, job.RunID, run)
		if run.Status == models.RunStatusCancelled {
			logger.Infof("Run %s was cancelled during plan execution", run.ID)
			return nil
		}

		// Check if timeout was exceeded
		if planCtx.Err() == context.DeadlineExceeded {
			logger.Infof("Plan operation exceeded timeout of %v for run %s", planTimeout, run.ID)
			run.Status = models.RunStatusFailed
			run.ErrorMessage = fmt.Sprintf("Plan operation exceeded timeout of %v and was automatically cancelled", planTimeout)
			if _, err := runRepo.CompleteIfNotCanceled(run); err != nil {
				return fmt.Errorf("failed to update run status: %w", err)
			}
			return nil
		}

		if err != nil {
			// TFE-compatible: If plan fails with provider error, re-run init and retry plan
			// This matches Terraform CLI behavior where it automatically re-initializes on provider errors
			if providerErr, ok := err.(*opentofu.ProviderError); ok {
				logger.Infof("Plan failed with provider error, re-running init: %v", providerErr)

				// Re-run init with upgrade to ensure providers are downloaded
				initResult, initErr := plugin.Init(ctx, terraformDir, nil, envVars)
				if initResult != nil {
					operationLogs.WriteString("\n=== Terraform Init (Retry) ===\n")
					operationLogs.WriteString(initResult.Logs)
					// Stream the re-init output into the same Redis log buffer as the rest
					// of the plan phase so the archived log (copied from Redis at finalize)
					// matches the live stream byte-for-byte, rather than a divergent
					// direct-to-storage write that would desync byte offsets (S1).
					if appendErr := logBufferService.Append(ctx, run.ID, "plan", "=== Terraform Init (Retry) ===\n"+initResult.Logs); appendErr != nil {
						logger.Warnf("Failed to append re-init logs to Redis for run %s: %v", run.ID, appendErr)
					}
				}
				if initErr != nil {
					logger.Infof("Re-init failed: %v", initErr)
					run.Status = models.RunStatusFailed
					run.ErrorMessage = fmt.Sprintf("Provider initialization failed: %v (original error: %v)", initErr, providerErr)
					run.CompletedAt = &now
					if _, err := runRepo.CompleteIfNotCanceled(run); err != nil {
						logger.Warnf("Failed to update run status: %v", err)
					}
					return fmt.Errorf("re-init failed after provider error: %w", initErr)
				}

				// Retry plan after successful re-init
				logger.Infof("Retrying plan after successful re-init")
				retryPlanOptions := &opentofu.PlanOptions{
					OnOutputLine: func(line string) {
						if err := logBufferService.Append(ctx, run.ID, "plan", line); err != nil {
							logger.Warnf("Failed to append plan log line to Redis (retry): %v", err)
						}
					},
					Destroy: run.Operation == models.RunOperationDestroy,
				}
				planResult, err = plugin.PlanWithOptions(ctx, terraformDir, variables, envVars, retryPlanOptions)
				if planResult != nil {
					operationLogs.WriteString("\n=== Terraform Plan (Retry) ===\n")
					operationLogs.WriteString(planResult.Logs)
					// Copy logs from Redis to storage for long-term persistence
					copyLogsFromRedisToStorage("plan")
				}

				// Check cancellation again
				run = reloadRun(runRepo, job.RunID, run)
				if run.Status == models.RunStatusCancelled {
					logger.Infof("Run %s was cancelled during plan retry", run.ID)
					return nil
				}

				if err != nil {
					run.Status = models.RunStatusFailed
					run.ErrorMessage = err.Error()
					if _, updateErr := runRepo.CompleteIfNotCanceled(run); updateErr != nil {
						logger.Warnf("Failed to update run status: %v", updateErr)
					}
				} else {
					// Store plan output with computed counts
					planOutput := make(models.PlanOutput)
					if planResult.JSONOutput != nil {
						for k, v := range planResult.JSONOutput {
							planOutput[k] = v
						}
					}
					// Add computed counts to PlanOutput for status checks
					planOutput["AddCount"] = float64(planResult.AddCount)
					planOutput["ChangeCount"] = float64(planResult.ChangeCount)
					planOutput["DestroyCount"] = float64(planResult.DestroyCount)
					planOutput["OutputChangeCount"] = float64(planResult.OutputChangeCount)
					run.PlanOutput = planOutput
					// Check if plan has changes (including output-only changes)
					hasChanges := planResult.AddCount > 0 || planResult.ChangeCount > 0 || planResult.DestroyCount > 0 || planResult.OutputChangeCount > 0
					// Set status based on run operation type
					now := time.Now()
					switch run.Operation {
					case models.RunOperationPlanAndApply:
						// Plan-and-apply run: If no changes, mark as completed (finished)
						// Otherwise, set to "planned" (waiting for apply)
						if !hasChanges {
							run.Status = models.RunStatusCompleted
							run.PlanCompletedAt = &now
							run.CompletedAt = &now
						} else {
							run.Status = models.RunStatusPlanned
							run.PlanCompletedAt = &now // Track when plan phase completed
						}
					case models.RunOperationPlanOnly:
						run.Status = models.RunStatusPlanned
						run.PlanCompletedAt = &now // Track when plan phase completed
						run.CompletedAt = &now     // Also set CompletedAt for plan-only runs (plan is complete)
					case models.RunOperationDestroy:
						// Destroy runs follow same logic as plan-and-apply
						if !hasChanges {
							run.Status = models.RunStatusCompleted
							run.PlanCompletedAt = &now
							run.CompletedAt = &now
						} else {
							run.Status = models.RunStatusPlanned
							run.PlanCompletedAt = &now
						}
					}
					if _, updateErr := runRepo.CompleteIfNotCanceled(run); updateErr != nil {
						logger.Warnf("Failed to update run status: %v", updateErr)
					}
				}
			} else {
				// Non-provider error, fail normally
				run.Status = models.RunStatusFailed
				run.ErrorMessage = err.Error()
				if _, updateErr := runRepo.CompleteIfNotCanceled(run); updateErr != nil {
					logger.Warnf("Failed to update run status: %v", updateErr)
				}
			}
		} else {
			// Store plan output with computed counts
			planOutput := make(models.PlanOutput)
			if planResult.JSONOutput != nil {
				for k, v := range planResult.JSONOutput {
					planOutput[k] = v
				}
			}
			// Add computed counts to PlanOutput for status checks
			planOutput["AddCount"] = float64(planResult.AddCount)
			planOutput["ChangeCount"] = float64(planResult.ChangeCount)
			planOutput["DestroyCount"] = float64(planResult.DestroyCount)
			planOutput["OutputChangeCount"] = float64(planResult.OutputChangeCount)
			run.PlanOutput = planOutput

			// Check if plan has changes (including output-only changes)
			hasChanges := planResult.AddCount > 0 || planResult.ChangeCount > 0 || planResult.DestroyCount > 0 || planResult.OutputChangeCount > 0

			// Compute the auto-apply decision ONCE, before any status write. It is consumed either
			// immediately (the shouldAutoApply transition below) or, when the run pauses at a
			// post_plan task stage, persisted as AutoApplyResolved so the run-task continuation
			// applies the SAME decision after the stage passes.
			shouldAutoApply := false
			autoApplyReason := ""
			if run.Operation == models.RunOperationPlanAndApply || run.Operation == models.RunOperationDestroy {
				// Auto-apply (transition plan->apply without a manual confirm) fires in two cases:
				//   1. a per-run auto-apply intent (go-tfe `auto-apply: true`, e.g. tfe_workspace_run
				//      fire-and-forget) -- explicit, applies regardless of VCS/workspace settings; or
				//   2. a VCS-triggered run in a workspace with AutoApply enabled.
				// Everything else (UI/CLI runs) waits for an explicit apply confirmation. This mirrors the
				// agent path in runner_agent.go -- both finalize paths must decide identically.
				if run.AutoApply {
					shouldAutoApply = true
					autoApplyReason = "per-run auto-apply intent (go-tfe auto-apply)"
				} else if run.ConfigurationVersionID != nil {
					configVersion, cvErr := configVersionRepo.GetByID(*run.ConfigurationVersionID)
					if cvErr == nil && configVersion != nil && configVersion.Source == "tfe-vcs" && workspace.AutoApply {
						shouldAutoApply = true
						autoApplyReason = "VCS-triggered with workspace auto-apply"
					}
				}
			}

			// Run-task gate: when the run has a post_plan task stage, pause at post_plan_running
			// instead of deciding planned/completed/applying here. The orchestrator fires the stage's
			// webhooks; the continuation (core/services/runtask.ContinueAfterStagePassed) later applies
			// the decision this function would have made, from the facts persisted here. Runs without
			// a stage row take the pre-run-tasks path below, byte-for-byte.
			hasPostPlanStage, tsErr := taskStageRepo.HasStage(run.ID, models.TaskStagePostPlan)
			if tsErr != nil {
				// Fail closed: skipping the gate on a transient DB error would let a run bypass a
				// mandatory task. The job errors and is retried.
				return fmt.Errorf("failed to check post_plan task stage for run %s: %w", run.ID, tsErr)
			}
			if hasPostPlanStage {
				now := time.Now()
				run.Status = models.RunStatusPostPlanRunning
				run.PlanCompletedAt = &now
				run.AutoApplyResolved = shouldAutoApply
				storePhaseState("plan")
				if ok, err := runRepo.CompleteIfNotCanceled(run); err != nil {
					return fmt.Errorf("failed to update run after plan (post_plan gate): %w", err)
				} else if !ok {
					logger.Infof("Run %s was canceled during plan; not entering post_plan task stage", run.ID)
					return nil
				}
				// The apply job (if the run gets that far) restores this exact plan (AUD-148).
				if hasChanges && (run.Operation == models.RunOperationPlanAndApply || run.Operation == models.RunOperationDestroy) {
					persistPlanFile()
				}
				logger.Infof("Run %s paused at post_plan task stage (auto-apply resolved: %v)", run.ID, shouldAutoApply)
				return nil
			}

			// Set status based on run operation type
			now := time.Now()
			switch run.Operation {
			case models.RunOperationPlanAndApply:
				// Plan-and-apply run: If no changes, mark as completed (finished)
				// Otherwise, set to "planned" (waiting for apply)
				if !hasChanges {
					run.Status = models.RunStatusCompleted
					run.PlanCompletedAt = &now
					run.CompletedAt = &now
				} else {
					run.Status = models.RunStatusPlanned
					run.PlanCompletedAt = &now // Track when plan phase completed
				}
			case models.RunOperationPlanOnly:
				// Plan-only run: Plan completed, set to "planned" (final state)
				run.Status = models.RunStatusPlanned
				run.PlanCompletedAt = &now // Track when plan phase completed
				run.CompletedAt = &now     // Also set CompletedAt for plan-only runs (plan is complete)
			case models.RunOperationDestroy:
				// Destroy runs follow same logic as plan-and-apply
				if !hasChanges {
					run.Status = models.RunStatusCompleted
					run.PlanCompletedAt = &now
					run.CompletedAt = &now
				} else {
					run.Status = models.RunStatusPlanned
					run.PlanCompletedAt = &now
				}
			}

			// Store parsed plan phase state for persistence
			if run.PlanCompletedAt != nil {
				storePhaseState("plan")
			}

			// Update run in database first. AUD-017: guarded so a Cancel that landed after the
			// post-plan cancellation check isn't clobbered back to planned/completed. If the run
			// was canceled, stop here - do not proceed to auto-apply.
			if ok, err := runRepo.CompleteIfNotCanceled(run); err != nil {
				return fmt.Errorf("failed to update run after plan: %w", err)
			} else if !ok {
				logger.Infof("Run %s was canceled during plan; not overwriting terminal status", run.ID)
				return nil
			}

			// TFE-compatible: Auto-apply logic
			// Only auto-apply for VCS-triggered configuration version runs with workspace.AutoApply enabled
			// Note: Run source is "tfe-configuration-version" for all runs created from configuration versions
			// We check the configuration version's source to determine if it's VCS-triggered
			// UI "Plan and Apply" runs should NOT auto-apply - they follow the 2-phase process:
			//   1. Plan runs and completes
			//   2. User sees plan output and clicks "Apply Plan" button
			//   3. Apply run is created via POST /api/v2/runs/:id/actions/apply
			// CLI runs should NEVER auto-apply (they're just for preview, prevents drift with git)
			//
			// The AutoApplyAfterPlan flag only indicates that this is a "plan-and-apply" run (not "plan-only"),
			// but it does NOT mean the run should auto-apply without user confirmation.
			// All UI-triggered runs require user confirmation via the Apply endpoint.
			if run.Operation == models.RunOperationPlanAndApply || run.Operation == models.RunOperationDestroy {
				// The decision was computed above (before the post_plan gate); apply it here for
				// runs without a post_plan task stage.
				if shouldAutoApply {
					logger.Infof("Plan-and-apply run %s plan phase completed, transitioning to applying phase (%s)", run.ID, autoApplyReason)

					// Transition to applying phase (orchestrator will pick it up)
					now := time.Now()
					run.Status = models.RunStatusApplying
					run.ApplyStartedAt = &now // Track when apply phase started
					run.UpdatedAt = now
					if _, err := runRepo.CompleteIfNotCanceled(run); err != nil {
						logger.Warnf("Failed to transition run %s to applying phase: %v", run.ID, err)
					} else {
						// Clear the dispatch claim consumed by the PLAN dispatch, or the orchestrator's
						// ClaimForDispatch for the apply phase can never succeed and the run wedges at
						// `applying` until the timeout reaper kills it. The manual-confirm path (Apply
						// endpoint) already did this; this auto-apply path never did (pre-existing bug,
						// found while wiring run tasks - see #554).
						if clearErr := runRepo.ClearDispatch(run.ID); clearErr != nil {
							logger.Warnf("Failed to clear dispatch claim for auto-applied run %s: %v", run.ID, clearErr)
						}
						logger.Infof("Run %s transitioned to applying phase, orchestrator will pick it up", run.ID)
					}
				} else {
					logger.Infof("Plan-and-apply run %s plan phase completed, waiting for user confirmation", run.ID)
				}
			}
		}

		// AUD-148: whichever plan branch ran (normal or provider-error retry), if the run is now
		// `planned` and an apply phase is still ahead, persist the saved plan so the separate apply
		// job can restore it after wiping the workspace dir.
		if run.Status == models.RunStatusPlanned &&
			(run.Operation == models.RunOperationPlanAndApply || run.Operation == models.RunOperationDestroy) {
			persistPlanFile()
		}
	}

	// Execute apply phase (for plan-and-apply runs in applying status)
	if executeApply {
		// Create timeout context for apply operation based on workspace timeout
		applyTimeout := time.Duration(workspace.RunTimeout) * time.Second
		if applyTimeout <= 0 {
			// Default to 2 hours if not configured
			applyTimeout = 2 * time.Hour
		}
		applyCtx, applyCancel := context.WithTimeout(ctx, applyTimeout)
		defer applyCancel()

		// Wrap with cancellation polling to detect cancellation during execution
		cancellableApplyCtx, cancelPolling := createCancellableContext(applyCtx, runRepo, run.ID)
		defer cancelPolling()

		logger.Infof("Starting apply operation with timeout of %v for run %s", applyTimeout, run.ID)

		// Use streaming Apply with callback to write logs to Redis
		applyOptions := &opentofu.ApplyOptions{
			OnOutputLine: func(line string) {
				if err := logBufferService.Append(cancellableApplyCtx, run.ID, "apply", line); err != nil {
					logger.Warnf("Failed to append apply log line to Redis: %v", err)
				}
			},
		}
		// AUD-148: this apply job wiped the workspace dir and re-extracted config, so the plan.out the
		// plan phase produced is gone. Restore the saved plan from storage before applying it.
		if err := restorePlanFile(); err != nil {
			logger.Warnf("Could not restore saved plan for run %s (apply will likely fail): %v", run.ID, err)
		}
		applyResult, err := plugin.ApplyWithOptions(cancellableApplyCtx, terraformDir, "plan.out", envVars, applyOptions)
		if applyResult != nil {
			operationLogs.WriteString("=== Terraform Apply ===\n")
			operationLogs.WriteString(applyResult.Logs)
		}
		// ALWAYS copy logs from Redis to storage, even if cancelled
		// Logs are already in Redis from streaming callback, even if applyResult is nil
		copyLogsFromRedisToStorage("apply")
		// AUD-148: the saved plan has now been consumed by apply; best-effort delete it from storage.
		if delErr := storageClient.Delete(ctx, planFileKey); delErr != nil {
			logger.Warnf("Failed to delete stored plan file for run %s: %v", run.ID, delErr)
		}
		// Check if run was cancelled during apply
		run = reloadRun(runRepo, job.RunID, run)
		if run.Status == models.RunStatusCancelled {
			logger.Infof("Run %s was cancelled during apply execution", run.ID)
			// TFE-compatible: Save partial state after cancelled apply
			// Terraform receives SIGINT on cancel and saves state for already-changed resources.
			// We must upload this partial state to prevent state drift and orphaned resources.
			storePhaseState("apply")
			stateFile := filepath.Join(terraformDir, "terraform.tfstate")
			if stateData, readErr := os.ReadFile(stateFile); readErr == nil { //nolint:gosec // stateFile is from workspace directory
				var stateJSON map[string]interface{}
				if jsonErr := json.Unmarshal(stateData, &stateJSON); jsonErr == nil {
					commitHash := ""
					committer := ""
					if run.ConfigurationVersionID != nil {
						cv, cvErr := configVersionRepo.GetByID(*run.ConfigurationVersionID)
						if cvErr == nil && cv != nil {
							commitHash = cv.CommitHash
							committer = cv.Committer
						}
					}
					runID := job.RunID
					stateSaveCtx, stateSaveCancel := context.WithTimeout(ctx, 30*time.Second)
					defer stateSaveCancel()
					if _, saveErr := stateService.SaveState(stateSaveCtx, job.WorkspaceID, stateJSON, &runID, commitHash, committer); saveErr != nil {
						logger.Warnf("Failed to save partial state after cancelled apply: %v", saveErr)
					} else {
						logger.Infof("Partial state saved successfully after cancelled apply for run %s", run.ID)
					}
				} else {
					logger.Warnf("Failed to parse partial state file after cancelled apply: %v", jsonErr)
				}
			} else {
				logger.Debugf("No state file found after cancelled apply (may be expected for first run): %v", readErr)
			}
			return nil
		}

		// Check if timeout was exceeded
		if applyCtx.Err() == context.DeadlineExceeded {
			logger.Infof("Apply operation exceeded timeout of %v for run %s", applyTimeout, run.ID)
			run.Status = models.RunStatusFailed
			run.ErrorMessage = fmt.Sprintf("Apply operation exceeded timeout of %v and was automatically cancelled", applyTimeout)
			if _, err := runRepo.CompleteIfNotCanceled(run); err != nil {
				return fmt.Errorf("failed to update run status: %w", err)
			}
			return nil
		}

		if err != nil {
			run.Status = models.RunStatusFailed
			run.ErrorMessage = err.Error()
			// Store phase state even on failure (to show completed resources)
			storePhaseState("apply")
		} else {
			// Set status based on run operation type
			applyCompletedAt := time.Now()
			if run.Operation == models.RunOperationPlanAndApply || run.Operation == models.RunOperationDestroy {
				// Run-task gate: a run with a post_apply task stage pauses at post_apply_running; the
				// continuation writes applied (+CompletedAt) after the stage passes. State saving below
				// still happens now - the infrastructure IS applied; only the run's terminal status
				// waits for the informational post-apply tasks.
				hasPostApplyStage, tsErr := taskStageRepo.HasStage(run.ID, models.TaskStagePostApply)
				if tsErr != nil {
					return fmt.Errorf("failed to check post_apply task stage for run %s: %w", run.ID, tsErr)
				}
				if hasPostApplyStage {
					run.Status = models.RunStatusPostApplyRunning
					logger.Infof("Run %s paused at post_apply task stage", run.ID)
				} else {
					// Plan-and-apply or destroy run: Apply phase completed
					run.Status = models.RunStatusApplied
					run.CompletedAt = &applyCompletedAt // Set CompletedAt when apply phase completes
				}
			} else {
				// This should not happen - apply phase should only execute for plan-and-apply or destroy runs
				logger.Warnf("Apply phase completed for unexpected run %s (operation: %s)", run.ID, run.Operation)
				run.Status = models.RunStatusFailed
				run.ErrorMessage = "Apply phase should only execute for plan-and-apply or destroy runs"
				run.CompletedAt = &applyCompletedAt
			}
			// Store parsed apply phase state for persistence
			storePhaseState("apply")

			// TFE-compatible: Save state after successful apply
			// Read terraform.tfstate file and create state version
			stateFile := filepath.Join(terraformDir, "terraform.tfstate")
			if stateData, readErr := os.ReadFile(stateFile); readErr == nil { //nolint:gosec // stateFile is from workspace directory, validated
				var stateJSON map[string]interface{}
				if jsonErr := json.Unmarshal(stateData, &stateJSON); jsonErr == nil {
					// Create state version via state service, linking to the run that created it
					// Extract commit info from run's configuration version if available (for VCS-triggered runs)
					commitHash := ""
					committer := ""
					if run.ConfigurationVersionID != nil {
						configVersion, err := configVersionRepo.GetByID(*run.ConfigurationVersionID)
						if err == nil && configVersion != nil {
							// Extract commit info from configuration version (set by VCS webhook)
							commitHash = configVersion.CommitHash
							committer = configVersion.Committer
						}
					}
					runID := job.RunID
					// Save state with timeout (30 seconds) to prevent hanging
					// Run status is already set to "applied" above, so state saving failure won't block status update
					stateSaveCtx, stateSaveCancel := context.WithTimeout(ctx, 30*time.Second)
					defer stateSaveCancel()
					if _, saveErr := stateService.SaveState(stateSaveCtx, job.WorkspaceID, stateJSON, &runID, commitHash, committer); saveErr != nil {
						logger.Warnf("Failed to save state after apply: %v", saveErr)
						// Don't fail the run if state saving fails, just log it
						// Run status is already set to "applied", so the run will complete successfully
					} else {
						logger.Infof("State saved successfully after apply for workspace %s", job.WorkspaceID)
					}
				} else {
					logger.Warnf("Failed to parse state file: %v", jsonErr)
				}
			} else {
				logger.Warnf("Failed to read state file: %v", readErr)
			}
		}
	}

	// Set CompletedAt for any run that doesn't have it set yet, but ONLY if run is in a terminal state
	// Don't set CompletedAt for runs that are still waiting (e.g., plan-and-apply runs in "planned" status waiting for apply)
	// Terminal states:
	// - applied, failed, canceled, completed: always terminal
	// - planned: terminal for plan-only runs, but NOT for plan-and-apply runs (they wait for apply)
	if run.CompletedAt == nil {
		isTerminal := false
		switch run.Status {
		case models.RunStatusApplied, models.RunStatusFailed, models.RunStatusCancelled, models.RunStatusCompleted:
			isTerminal = true
		case models.RunStatusPlanned:
			// "planned" is terminal for plan-only runs, but NOT for plan-and-apply runs
			isTerminal = (run.Operation == models.RunOperationPlanOnly)
		case models.RunStatusPending, models.RunStatusPlanning, models.RunStatusApplying, models.RunStatusRunning,
			models.RunStatusPrePlanRunning, models.RunStatusPrePlanCompleted,
			models.RunStatusPostPlanRunning, models.RunStatusPostPlanCompleted,
			models.RunStatusPreApplyRunning, models.RunStatusPreApplyCompleted,
			models.RunStatusPostApplyRunning, models.RunStatusPostApplyCompleted:
			// Non-terminal states, including every run-task stage state: the run-task continuation
			// (or its plan-only rest write) owns CompletedAt for those.
			isTerminal = false
		}

		if isTerminal {
			now := time.Now()
			run.CompletedAt = &now
		}
	}
	// AUD-017: guarded terminal write - a Cancel that raced the apply's completion (between the
	// post-apply cancellation check and here) must not be clobbered back to applied/failed.
	if ok, err := runRepo.CompleteIfNotCanceled(run); err != nil {
		return fmt.Errorf("failed to update run: %w", err)
	} else if !ok {
		logger.Infof("Run %s was canceled during apply; not overwriting terminal status", run.ID)
	}

	logger.Infof("Job completed: RunID=%s, Status=%s", job.RunID, run.Status)
	return nil
}

// extractTarGz extracts a gzipped tarball ([]byte) to a directory
// TFE stores configuration files as tar.gz archives
// reloadRun re-fetches the run to observe a concurrent cancellation, returning the previous value
// on error instead of nil (AUD-027). The prior code did `run, _ = runRepo.GetByID(...)` and then
// immediately dereferenced run.Status - a transient DB error nil-deref'd and crashed the runner
// mid-job, which then compounded into a stuck run (AUD-016).
func reloadRun(runRepo *repository.RunRepository, runID string, prev *models.Run) *models.Run {
	reloaded, err := runRepo.GetByID(runID)
	if err != nil {
		logger.Warnf("Failed to reload run %s to check cancellation, keeping last-known status: %v", runID, err)
		return prev
	}
	return reloaded
}

func extractTarGz(data []byte, destDir string) error {
	gzipReader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer func() {
		if err := gzipReader.Close(); err != nil {
			logger.Warnf("Failed to close gzip reader: %v", err)
		}
	}()

	tarReader := tar.NewReader(gzipReader)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read tar header: %w", err)
		}

		targetPath := filepath.Join(destDir, header.Name) //nolint:gosec // path traversal protection below

		// Security: Prevent directory traversal - ensure targetPath is within destDir
		cleanTargetPath := filepath.Clean(targetPath)
		cleanDestDir := filepath.Clean(destDir)
		if !strings.HasPrefix(cleanTargetPath, cleanDestDir+string(filepath.Separator)) && cleanTargetPath != cleanDestDir {
			return fmt.Errorf("invalid file path (directory traversal attempt): %s", header.Name)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			// Security: Validate directory mode to prevent integer overflow
			dirMode := header.Mode & 0o777 // Only use permission bits
			if dirMode > 0o777 {
				dirMode = 0o750 // Default to safe permissions if invalid
			}
			if err := os.MkdirAll(targetPath, os.FileMode(dirMode)); err != nil { //nolint:gosec // dirMode is validated above
				return fmt.Errorf("failed to create directory: %w", err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(targetPath), 0o750); err != nil { //nolint:gosec // G703: targetPath is validated against workspace directory before extraction
				return fmt.Errorf("failed to create parent directory: %w", err)
			}
			// Security: Validate file mode to prevent integer overflow
			fileMode := header.Mode & 0o777 // Only use permission bits
			if fileMode > 0o777 {
				fileMode = 0o644 // Default to safe permissions if invalid
			}
			file, err := os.OpenFile(targetPath, os.O_CREATE|os.O_RDWR|os.O_TRUNC, os.FileMode(fileMode)) //nolint:gosec // fileMode is validated above
			if err != nil {
				return fmt.Errorf("failed to create file: %w", err)
			}
			// Security: Limit decompression size to prevent decompression bombs (100MB limit)
			const maxDecompressedSize = 100 * 1024 * 1024 // 100MB
			limitedReader := io.LimitReader(tarReader, maxDecompressedSize)
			if _, err := io.Copy(file, limitedReader); err != nil {
				if closeErr := file.Close(); closeErr != nil {
					logger.Warnf("Failed to close file after copy error: %v", closeErr)
				}
				return fmt.Errorf("failed to write file: %w", err)
			}
			if err := file.Close(); err != nil {
				logger.Warnf("Failed to close file: %v", err)
			}
		default:
			// Skip other types (symlinks, etc.)
			logger.Infof("Skipping unsupported file type: %s (type: %c)", header.Name, header.Typeflag)
		}
	}

	return nil
}

// filterLocalPathMessages filters out local file path messages from logs
// TFE-compatible: Remote execution doesn't show "Saved the plan to: /path/to/plan.out" messages
// func filterLocalPathMessages(logs string) string {
// 	lines := strings.Split(logs, "\n")
// 	var filtered []string
// 	for _, line := range lines {
// 		// Filter out "Saved the plan to:" messages (local backend artifact)
// 		if strings.Contains(line, "Saved the plan to:") {
// 			continue
// 		}
// 		// Filter out "To perform exactly these actions, run:" messages (not applicable for remote execution)
// 		if strings.Contains(line, "To perform exactly these actions, run:") {
// 			continue
// 		}
// 		filtered = append(filtered, line)
// 	}
// 	return strings.Join(filtered, "\n")
// }

// replaceRemoteBackendWithLocal replaces remote backend with local backend in terraform config files
// This prevents the runner from creating nested runs when executing terraform commands
// TFE-compatible: Remote execution should use local state, not remote backend
func replaceRemoteBackendWithLocal(workspaceDir string) error {
	// AUD-080: scan every *.tf file in the directory (not a fixed four-name list that misses
	// non-standard filenames) and strip both TFC/TFE `cloud {}` blocks and `backend "remote"`
	// blocks - matching the agent runner (agent_mode.go), which the platform runner had drifted
	// from. Without the `cloud {}` removal a config using the newer cloud block would try to run
	// against TFC/TFE from inside the runner.
	entries, err := os.ReadDir(workspaceDir)
	if err != nil {
		return fmt.Errorf("failed to list workspace directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".tf") {
			continue
		}
		filePath := filepath.Join(workspaceDir, entry.Name())
		content, err := os.ReadFile(filePath) //nolint:gosec // filePath is from workspace directory, validated
		if err != nil {
			continue
		}

		contentStr := string(content)
		newContent := replaceRemoteBackendInContent(contentStr)

		if newContent != contentStr {
			if err := os.WriteFile(filePath, []byte(newContent), 0o600); err != nil { //nolint:gosec // G703: filePath is from workspace directory, validated before use
				return fmt.Errorf("failed to write %s: %w", entry.Name(), err)
			}
			logger.Infof("Replaced remote backend with local backend in %s", entry.Name())
		}
	}

	return nil
}

// replaceRemoteBackendInContent removes `cloud {}` blocks and rewrites `backend "remote"` to a
// local backend, so remote execution uses local state rather than nesting a run against TFC/TFE.
func replaceRemoteBackendInContent(contentStr string) string {
	// Remove any cloud { ... } block (used by TFC/TFE) - same helper the agent runner uses.
	newContent := removeHCLBlock(contentStr, "cloud {")

	if !strings.Contains(newContent, "backend \"remote\"") {
		return newContent
	}

	// Replace remote backend with a local backend. Try the nested-brace-aware regex first.
	re := regexp.MustCompile(`(?s)backend\s+"remote"\s*\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}`)
	replacement := `backend "local" {
  path = "terraform.tfstate"
}`
	replaced := re.ReplaceAllString(newContent, replacement)

	// If the regex didn't match (deeply nested braces), fall back to manual brace matching.
	if replaced == newContent {
		startIdx := strings.Index(newContent, `backend "remote"`)
		if startIdx != -1 {
			braceStart := strings.Index(newContent[startIdx:], "{")
			if braceStart != -1 {
				braceStart += startIdx
				braceCount := 0
				endIdx := braceStart
				for i := braceStart; i < len(newContent); i++ {
					if newContent[i] == '{' {
						braceCount++
					} else if newContent[i] == '}' {
						braceCount--
						if braceCount == 0 {
							endIdx = i + 1
							break
						}
					}
				}
				replaced = newContent[:startIdx] + replacement + newContent[endIdx:]
			}
		}
	}

	return replaced
}
