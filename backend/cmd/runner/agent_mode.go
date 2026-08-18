// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/michielvha/logger"
	"github.com/michielvha/stackweaver/core/security/gitargs"
	"github.com/michielvha/stackweaver/core/tofu"
)

// TFAgentConfig holds configuration for agent mode
type TFAgentConfig struct {
	ServerURL    string
	Token        string
	AgentPoolID  string
	RunnerName   string
	Labels       []string
	PollInterval time.Duration
}

// TFAgentRunner handles the agent mode lifecycle for Terraform
type TFAgentRunner struct {
	config        TFAgentConfig
	runnerID      string
	runnerToken   string // Runner-scoped API key minted at registration (AUD-001); used for all control-plane calls
	client        *http.Client
	shutdown      chan struct{}
	planJSONCache string // Stores plan JSON from the last plan phase for sending with completion
}

// authToken returns the credential for a control-plane call: the runner-scoped
// token once registered, otherwise the org registration key (used only for the
// initial /runner/register). AUD-001: post-registration calls authenticate as the
// specific runner, not with the shared org key.
func (a *TFAgentRunner) authToken() string {
	if a.runnerToken != "" {
		return a.runnerToken
	}
	return a.config.Token
}

// TFRegisterResponse is the response from the register endpoint
type TFRegisterResponse struct {
	RunnerID            string `json:"runner_id"`
	RunnerAPIKey        string `json:"runner_api_key"`
	PollIntervalSeconds int    `json:"poll_interval_seconds"`
}

// TFHeartbeatResponse is the response from the heartbeat endpoint
type TFHeartbeatResponse struct {
	PendingJobs []TFPendingJob `json:"pending_jobs"`
}

// TFPendingJob represents a Terraform job waiting to be executed
type TFPendingJob struct {
	JobID         string `json:"job_id"`
	JobType       string `json:"job_type"`
	WorkspaceID   string `json:"workspace_id"`
	WorkspaceName string `json:"workspace_name"`
	RunType       string `json:"run_type,omitempty"` // plan, apply, destroy
	Priority      int    `json:"priority"`
}

// TFJobArtifacts contains all files needed for Terraform execution
type TFJobArtifacts struct {
	ConfigTarball    string            `json:"config_tarball,omitempty"`    // base64 encoded tarball
	Variables        map[string]string `json:"variables,omitempty"`         // Terraform variables
	VariablesHCL     []string          `json:"variables_hcl,omitempty"`     // Keys in Variables that are HCL-typed (AUD-022)
	EnvironmentVars  map[string]string `json:"environment_vars,omitempty"`  // Environment variables
	BackendConfig    string            `json:"backend_config,omitempty"`    // Backend configuration
	TofuVersion      string            `json:"tofu_version,omitempty"`      // Required OpenTofu version
	WorkingDirectory string            `json:"working_directory,omitempty"` // Working directory within config
	VCS              *TFVCSInfo        `json:"vcs,omitempty"`               // VCS info for cloning
	StateJSON        string            `json:"state_json,omitempty"`        // Latest state JSON (base64 encoded) to restore before execution
}

// TFVCSInfo contains VCS repository info for cloning
type TFVCSInfo struct {
	RepoURL    string `json:"repo_url"`
	Branch     string `json:"branch"`
	Repository string `json:"repository"`
}

// RunAgentMode starts the OpenTofu runner in agent mode
func RunAgentMode() {
	config := loadTFAgentConfig()

	agent := &TFAgentRunner{
		config:   config,
		client:   &http.Client{Timeout: 30 * time.Second},
		shutdown: make(chan struct{}),
	}

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		logger.Info("Received shutdown signal, gracefully stopping...")
		close(agent.shutdown)
	}()

	// Register with the server
	if err := agent.register(); err != nil {
		logger.Fatalf("Failed to register runner: %v", err)
	}

	logger.Infof("OpenTofu runner registered successfully with ID: %s", agent.runnerID)
	logger.Infof("Starting heartbeat loop (poll interval: %v)", agent.config.PollInterval)

	// Start heartbeat loop
	agent.heartbeatLoop()

	// Deregister on shutdown
	agent.deregister()
	logger.Info("OpenTofu runner shut down cleanly")
}

// loadTFAgentConfig loads agent configuration from environment
func loadTFAgentConfig() TFAgentConfig {
	serverURL := os.Getenv("STACKWEAVER_SERVER")
	if serverURL == "" {
		logger.Fatal("STACKWEAVER_SERVER environment variable is required")
	}

	token := os.Getenv("STACKWEAVER_TOKEN")
	if token == "" {
		logger.Fatal("STACKWEAVER_TOKEN environment variable is required")
	}

	agentPoolID := os.Getenv("RUNNER_AGENT_POOL_ID")
	if agentPoolID == "" {
		logger.Fatal("RUNNER_AGENT_POOL_ID environment variable is required")
	}

	runnerName := os.Getenv("RUNNER_NAME")
	if runnerName == "" {
		hostname, _ := os.Hostname()
		runnerName = fmt.Sprintf("terraform-runner-%s", hostname)
	}

	var labels []string
	if labelsStr := os.Getenv("RUNNER_LABELS"); labelsStr != "" {
		for _, l := range strings.Split(labelsStr, ",") {
			if trimmed := strings.TrimSpace(l); trimmed != "" {
				labels = append(labels, trimmed)
			}
		}
	}

	pollInterval := 10 * time.Second
	if intervalStr := os.Getenv("POLL_INTERVAL"); intervalStr != "" {
		if d, err := time.ParseDuration(intervalStr); err == nil {
			pollInterval = d
		}
	}

	return TFAgentConfig{
		ServerURL:    serverURL,
		Token:        token,
		AgentPoolID:  agentPoolID,
		RunnerName:   runnerName,
		Labels:       labels,
		PollInterval: pollInterval,
	}
}

// register registers this runner with the server
func (a *TFAgentRunner) register() error {
	// Get OpenTofu version
	tfVersion := getTofuVersion()

	payload := map[string]interface{}{
		"agent_pool_id":       a.config.AgentPoolID,
		"name":                a.config.RunnerName,
		"runner_type":         "tofu",
		"hostname":            getHostname(),
		"os_type":             runtime.GOOS,
		"os_arch":             runtime.GOARCH,
		"tofu_version":        tfVersion,
		"labels":              a.config.Labels,
		"max_concurrent_jobs": 1,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal register payload: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", a.config.ServerURL+"/api/v2/runner/register", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create register request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	// Registration always authenticates with the org registration key (runner:register
	// scope); the runner-scoped token cannot register. All other calls use authToken().
	req.Header.Set("Authorization", "Bearer "+a.config.Token)

	resp, err := a.client.Do(req) //nolint:gosec // G704: URL is the operator-configured server endpoint, not user-controlled
	if err != nil {
		return fmt.Errorf("failed to send register request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("registration failed (status %d): %s", resp.StatusCode, string(respBody))
	}

	var registerResp TFRegisterResponse
	if err := json.NewDecoder(resp.Body).Decode(&registerResp); err != nil {
		return fmt.Errorf("failed to decode register response: %w", err)
	}

	a.runnerID = registerResp.RunnerID
	if registerResp.RunnerAPIKey != "" {
		a.runnerToken = registerResp.RunnerAPIKey
	}
	return nil
}

// heartbeatLoop continuously sends heartbeats and processes pending jobs
func (a *TFAgentRunner) heartbeatLoop() {
	ticker := time.NewTicker(a.config.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-a.shutdown:
			return
		case <-ticker.C:
			pendingJobs, err := a.sendHeartbeat("online", 0)
			if err != nil {
				logger.Warnf("Heartbeat failed: %v", err)
				continue
			}

			// Process pending jobs
			for _, job := range pendingJobs {
				select {
				case <-a.shutdown:
					return
				default:
					a.executeJob(job)
				}
			}
		}
	}
}

// sendHeartbeat sends a heartbeat to the server and returns pending jobs
func (a *TFAgentRunner) sendHeartbeat(status string, currentJobs int) ([]TFPendingJob, error) {
	payload := map[string]interface{}{
		"runner_id":    a.runnerID,
		"status":       status,
		"current_jobs": currentJobs,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal heartbeat payload: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", a.config.ServerURL+"/api/v2/runner/heartbeat", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create heartbeat request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+a.authToken())

	resp, err := a.client.Do(req) //nolint:gosec // G704: URL is the operator-configured server endpoint, not user-controlled
	if err != nil {
		return nil, fmt.Errorf("failed to send heartbeat: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("heartbeat failed (status %d): %s", resp.StatusCode, string(respBody))
	}

	var heartbeatResp TFHeartbeatResponse
	if err := json.NewDecoder(resp.Body).Decode(&heartbeatResp); err != nil {
		return nil, fmt.Errorf("failed to decode heartbeat response: %w", err)
	}

	return heartbeatResp.PendingJobs, nil
}

// executeJob downloads and executes a Terraform job
func (a *TFAgentRunner) executeJob(job TFPendingJob) {
	logger.Infof("Executing Terraform job %s (type: %s, workspace: %s)", job.JobID, job.RunType, job.WorkspaceName)

	// Update status to busy
	_, _ = a.sendHeartbeat("busy", 1)

	// AUD-025: executeJob runs synchronously inside the heartbeat loop, so no heartbeats are sent
	// for the full duration of a job. A job longer than the monitor's 30s offline threshold would
	// flip this runner offline mid-run. Keep pinging "busy" until the job returns.
	stopKeepalive := a.startHeartbeatKeepalive()
	defer stopKeepalive()

	// Notify job start
	if err := a.notifyJobStart(job.JobID); err != nil {
		logger.Warnf("Failed to notify job start: %v", err)
	}

	// Download job artifacts
	artifacts, err := a.downloadJobArtifacts(job.JobID)
	if err != nil {
		logger.Errorf("Failed to download job artifacts: %v", err)
		a.notifyJobComplete(job.JobID, "failed", fmt.Sprintf("Failed to download artifacts: %v", err))
		return
	}

	// Clear plan JSON cache for each new job
	a.planJSONCache = ""

	// Execute Terraform (polls for cancellation; returns cancelled=true if run was cancelled)
	exitCode, output, err, cancelled := a.runTerraform(job, artifacts)
	if cancelled {
		logger.Infof("Terraform job %s was cancelled", job.JobID)
		a.notifyJobComplete(job.JobID, "canceled", output)
		_, _ = a.sendHeartbeat("online", 0)
		return
	}
	if err != nil {
		logger.Errorf("Terraform execution failed: %v", err)
		errMsg := fmt.Sprintf("Execution failed: %v", err)
		if output != "" {
			errMsg = fmt.Sprintf("%s\n\nOutput:\n%s", errMsg, output)
			logger.Errorf("Execution output: %s", output)
		}
		a.notifyJobComplete(job.JobID, "failed", errMsg)
		return
	}

	// Determine status based on exit code
	status := "completed"
	if exitCode != 0 {
		status = "failed"
	}

	a.notifyJobComplete(job.JobID, status, output)
	logger.Infof("Terraform job %s completed with status: %s", job.JobID, status)

	// Update status back to online
	_, _ = a.sendHeartbeat("online", 0)
}

// startHeartbeatKeepalive sends periodic "busy" heartbeats until the returned stop func is called,
// so a runner executing a long job (which blocks the heartbeat loop) is not marked offline by the
// server-side monitor after 30s (AUD-025). The stop func blocks until the goroutine has exited.
func (a *TFAgentRunner) startHeartbeatKeepalive() func() {
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-a.shutdown:
				return
			case <-ticker.C:
				_, _ = a.sendHeartbeat("busy", 1)
			}
		}
	}()
	return func() {
		close(stop)
		<-done
	}
}

// downloadJobArtifacts downloads all artifacts needed for the job
func (a *TFAgentRunner) downloadJobArtifacts(jobID string) (*TFJobArtifacts, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", a.config.ServerURL+"/api/v2/runner/jobs/"+jobID+"/artifacts", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create artifacts request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+a.authToken())

	resp, err := a.client.Do(req) //nolint:gosec // G704: URL is the operator-configured server endpoint, not user-controlled
	if err != nil {
		return nil, fmt.Errorf("failed to send artifacts request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("artifacts download failed (status %d): %s", resp.StatusCode, string(respBody))
	}

	var artifacts TFJobArtifacts
	if err := json.NewDecoder(resp.Body).Decode(&artifacts); err != nil {
		return nil, fmt.Errorf("failed to decode artifacts: %w", err)
	}

	return &artifacts, nil
}

// getJobStatus fetches the run status from the API (for cancellation polling).
func (a *TFAgentRunner) getJobStatus(ctx context.Context, jobID string) (string, error) {
	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, "GET", a.config.ServerURL+"/api/v2/runner/jobs/"+jobID+"/status", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+a.authToken())
	resp, err := a.client.Do(req) //nolint:gosec // G704: URL is the operator-configured server endpoint, not user-controlled
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status %d", resp.StatusCode)
	}
	var out struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	return out.Status, nil
}

// runTerraform executes terraform with the given artifacts.
// It polls the API for run cancellation and returns cancelled=true if the run was cancelled.
func (a *TFAgentRunner) runTerraform(job TFPendingJob, artifacts *TFJobArtifacts) (exitCode int, output string, err error, cancelled bool) {
	// Create working directory
	workDir, mkErr := os.MkdirTemp("", "terraform-job-"+job.JobID)
	if mkErr != nil {
		return 1, "", fmt.Errorf("failed to create work dir: %w", mkErr), false
	}
	defer func() { _ = os.RemoveAll(workDir) }()

	// Extract config tarball if provided (base64-encoded tar.gz)
	switch {
	case artifacts.ConfigTarball != "":
		tarballData, err := base64.StdEncoding.DecodeString(artifacts.ConfigTarball)
		if err != nil {
			return 1, "", fmt.Errorf("failed to decode config tarball: %w", err), false
		}
		if err := extractTarGzForAgent(tarballData, workDir); err != nil {
			return 1, "", fmt.Errorf("failed to extract config tarball: %w", err), false
		}
		logger.Infof("Extracted configuration tarball to %s", workDir)
	case artifacts.VCS != nil && artifacts.VCS.RepoURL != "":
		// Clone VCS repository if no config tarball
		// Log clone URL with token masked for debugging
		maskedURL := artifacts.VCS.RepoURL
		if idx := strings.Index(maskedURL, "x-access-token:"); idx != -1 {
			atIdx := strings.Index(maskedURL[idx:], "@")
			if atIdx != -1 {
				maskedURL = maskedURL[:idx] + "x-access-token:***" + maskedURL[idx+atIdx:]
			}
		}
		logger.Infof("Cloning repository %s (branch: %s) URL: %s", artifacts.VCS.Repository, artifacts.VCS.Branch, maskedURL)
		branch := artifacts.VCS.Branch
		if branch == "" {
			branch = "main"
		}
		// AUD-043: the branch/URL originate from user-set workspace VCS config; git parses "-"-leading
		// args as options (CVE-2017-1000117 class). Guard both inline and place "--" before the
		// positionals so a smuggled option can't reach git.
		if !gitargs.RefNameRe.MatchString(branch) {
			return 1, "", fmt.Errorf("refusing unsafe branch name %q", branch), false
		}
		if !gitargs.GitURLRe.MatchString(artifacts.VCS.RepoURL) {
			return 1, "", fmt.Errorf("refusing unsafe repository URL"), false
		}
		cloneCmd := exec.Command("git", "clone", "--depth", "1", "--branch", branch, "--", artifacts.VCS.RepoURL, workDir) //nolint:gosec,noctx // G204: branch + RepoURL validated inline above; positionals guarded by "--"
		if out, err := cloneCmd.CombinedOutput(); err != nil {
			logger.Errorf("Git clone failed: %s", string(out))
			return 1, string(out), fmt.Errorf("failed to clone repo: %s: %w", string(out), err), false
		}
		logger.Infof("Repository cloned successfully to %s", workDir)
	default:
		logger.Warnf("No config tarball and no VCS info available for job %s (VCS nil=%v)", job.JobID, artifacts.VCS == nil)
	}

	// Handle working directory
	terraformDir := workDir
	if artifacts.WorkingDirectory != "" && artifacts.WorkingDirectory != "." && artifacts.WorkingDirectory != "/" {
		terraformDir = filepath.Join(workDir, strings.TrimPrefix(artifacts.WorkingDirectory, "/"))
		// AUD-074: reject a working directory that escapes the per-job temp dir (e.g. "../../etc").
		if terraformDir != workDir && !strings.HasPrefix(terraformDir, workDir+string(os.PathSeparator)) {
			return 1, "", fmt.Errorf("invalid working directory (escapes job root): %s", artifacts.WorkingDirectory), false
		}
		logger.Infof("Using working directory: %s", terraformDir)
	}

	// AWS OIDC (self-hosted agent): the handler passed the web identity token as a raw env value
	// because it can't write files on this host; materialize it to a file for terraform-provider-aws.
	if artifacts.EnvironmentVars != nil {
		if err := materializeAWSWebIdentityToken(artifacts.EnvironmentVars, terraformDir); err != nil {
			logger.Warnf("Failed to materialize AWS web identity token for job %s: %v", job.JobID, err)
		}
	}

	// GCP OIDC (self-hosted agent): the handler passed the raw token + config attrs because it can't
	// write files on this host; materialize the token + credential-config JSON for the google provider.
	if artifacts.EnvironmentVars != nil {
		if err := materializeGCPWorkloadIdentity(artifacts.EnvironmentVars, terraformDir); err != nil {
			logger.Warnf("Failed to materialize GCP workload identity for job %s: %v", job.JobID, err)
		}
	}

	// Vault OIDC (self-hosted agent): only the agent can reach the customer's Vault, so it performs the
	// JWT login here with the injected raw token and exports VAULT_ADDR + VAULT_TOKEN for the run.
	if artifacts.EnvironmentVars != nil {
		vaultCtx, cancelVault := context.WithTimeout(context.Background(), 30*time.Second)
		if err := materializeVaultToken(vaultCtx, artifacts.EnvironmentVars, terraformDir); err != nil {
			logger.Warnf("Failed to materialize Vault token for job %s: %v", job.JobID, err)
		}
		cancelVault()
	}

	// Write terraform.tfvars if variables are provided
	if len(artifacts.Variables) > 0 {
		// AUD-022: HCL-typed variables must be emitted as raw unquoted expressions; the API tells
		// us which keys are HCL via VariablesHCL. Everything else is quoted as a string.
		hclKeys := make(map[string]struct{}, len(artifacts.VariablesHCL))
		for _, k := range artifacts.VariablesHCL {
			hclKeys[k] = struct{}{}
		}
		var tfvarsContent strings.Builder
		for key, value := range artifacts.Variables {
			if _, isHCL := hclKeys[key]; isHCL {
				_, _ = fmt.Fprintf(&tfvarsContent, "%s = %s\n", key, value)
			} else {
				// Quote string values for tfvars format
				_, _ = fmt.Fprintf(&tfvarsContent, "%s = %q\n", key, value)
			}
		}
		tfvarsPath := filepath.Join(terraformDir, "stackweaver.auto.tfvars")
		if err := os.WriteFile(tfvarsPath, []byte(tfvarsContent.String()), 0o600); err != nil {
			return 1, "", fmt.Errorf("failed to write tfvars: %w", err), false
		}
		logger.Infof("Wrote %d variables to stackweaver.auto.tfvars", len(artifacts.Variables))
	}

	// Replace remote backend with local backend (prevent infinite loop)
	replaceRemoteBackendForAgent(terraformDir)

	// TFE-compatible: Restore latest state from platform before running terraform
	// The self-hosted runner uses a fresh temp dir per job, so state must be downloaded
	// from the platform to ensure terraform knows about existing resources.
	if artifacts.StateJSON != "" {
		stateData, decErr := base64.StdEncoding.DecodeString(artifacts.StateJSON)
		if decErr != nil {
			logger.Warnf("Failed to decode state JSON from artifacts: %v", decErr)
		} else {
			stateFilePath := filepath.Join(terraformDir, "terraform.tfstate")
			if writeErr := os.WriteFile(stateFilePath, stateData, 0o600); writeErr != nil {
				logger.Warnf("Failed to write state file: %v", writeErr)
			} else {
				logger.Infof("Restored state file (%d bytes) for job %s", len(stateData), job.JobID)
			}
		}
	}

	// Resolve the correct terraform binary for the workspace version (like TFE)
	tfBinary := resolveTofuBinary(artifacts.TofuVersion)
	logger.Infof("Using opentofu binary: %s (requested version: %s)", tfBinary, artifacts.TofuVersion)

	// Run terraform init first
	logger.Infof("Running terraform init in %s", terraformDir)
	// #nosec G204 -- args are constructed from trusted sources
	initCmd := exec.Command(tfBinary, "init", "-no-color", "-input=false", "-reconfigure") //nolint:gosec,noctx // G204: intentional opentofu execution; no long-running context needed
	initCmd.Dir = terraformDir
	initCmd.Env = os.Environ()
	for k, v := range artifacts.EnvironmentVars {
		initCmd.Env = append(initCmd.Env, k+"="+v)
	}
	initOut, initErr := initCmd.CombinedOutput()
	if initErr != nil {
		logger.Errorf("Terraform init output: %s", string(initOut))
		return 1, string(initOut), fmt.Errorf("opentofu init failed: %s: %w", string(initOut), initErr), false
	}
	logger.Infof("Terraform init completed successfully")

	// Determine terraform command based on run type
	// TFE-compatible: Destroy runs follow the same two-phase flow as plan-and-apply:
	// Phase 1 (plan-destroy): terraform plan -destroy -out=tfplan
	// Phase 2 (apply): terraform apply -auto-approve tfplan
	isPlan := false
	var args []string
	switch job.RunType {
	case "plan", "plan-only":
		// Use -out to save the plan file for later JSON inspection
		args = []string{"plan", "-no-color", "-input=false", "-out=tfplan"}
		isPlan = true
	case "plan-destroy":
		// Destroy plan phase: show what will be destroyed, save plan file
		args = []string{"plan", "-destroy", "-no-color", "-input=false", "-out=tfplan"}
		isPlan = true
	case "apply":
		// Apply phase (for plan-and-apply runs)
		// Self-hosted runners run in fresh temp dirs per job, so plan file won't persist
		args = []string{"apply", "-no-color", "-input=false", "-auto-approve"}
		isPlan = false
	case "apply-destroy":
		// Apply-destroy phase: execute the destroy (for destroy runs)
		// Uses terraform apply -destroy since self-hosted runners don't persist plan files
		args = []string{"apply", "-destroy", "-no-color", "-input=false", "-auto-approve"}
		isPlan = false
	default:
		args = []string{"plan", "-no-color", "-input=false", "-out=tfplan"}
		isPlan = true
	}

	// Build environment for terraform commands
	tfEnv := os.Environ()
	for k, v := range artifacts.EnvironmentVars {
		tfEnv = append(tfEnv, k+"="+v)
	}

	// Cancellable context: poll API for run cancellation and cancel to stop terraform
	runCtx, cancelRun := context.WithCancel(context.Background())
	defer cancelRun()
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-runCtx.Done():
				return
			case <-ticker.C:
				status, pollErr := a.getJobStatus(runCtx, job.JobID)
				if pollErr != nil {
					continue
				}
				if status == "canceled" {
					logger.Infof("Run %s was cancelled, stopping terraform", job.JobID)
					cancelRun()
					return
				}
			}
		}
	}()

	// Execute terraform (context is cancelled when run is cancelled via API)
	// #nosec G204 -- args are constructed from trusted sources
	cmd := exec.CommandContext(runCtx, tfBinary, args...) //nolint:gosec
	cmd.Dir = terraformDir
	cmd.Env = tfEnv

	// TFE-compatible: Send SIGINT on cancel instead of SIGKILL
	// This allows Terraform to save state for already-changed resources (like Ctrl+C)
	cmd.Cancel = func() error {
		if cmd.Process != nil {
			return cmd.Process.Signal(syscall.SIGINT)
		}
		return nil
	}
	// Give Terraform up to 60 seconds to save state after SIGINT before force-killing
	cmd.WaitDelay = 60 * time.Second

	// Determine log phase for streaming - must match how the log retrieval API determines phase
	var logPhase string
	switch job.RunType {
	case "apply", "apply-destroy":
		logPhase = "apply"
	default:
		logPhase = "plan"
	}

	streamBuf := &bytes.Buffer{}
	fullOutput := &bytes.Buffer{}
	streamer := &tfStreamWriter{
		agent:    a,
		jobID:    job.JobID,
		phase:    logPhase,
		buffer:   streamBuf,
		lastSend: time.Now(),
	}
	cmd.Stdout = io.MultiWriter(streamer, fullOutput, os.Stdout)
	cmd.Stderr = io.MultiWriter(streamer, fullOutput, os.Stderr)

	err = cmd.Run()
	streamer.flush()

	if runCtx.Err() == context.Canceled {
		// TFE-compatible: Upload partial state after cancelled apply
		// Terraform received SIGINT and had time to save state for already-changed resources.
		// We must upload this partial state to prevent state drift and orphaned resources.
		if !isPlan {
			a.extractAndUploadState(tfBinary, terraformDir, tfEnv, job.JobID)
		}
		return 1, fullOutput.String(), err, true
	}

	exitCode = 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			return 1, fullOutput.String(), err, false
		}
	}

	if isPlan && exitCode == 0 {
		planJSON := a.extractPlanJSON(tfBinary, terraformDir, tfEnv)
		if planJSON != "" {
			a.planJSONCache = planJSON
		}
	}
	if !isPlan && exitCode == 0 {
		a.extractAndUploadState(tfBinary, terraformDir, tfEnv, job.JobID)
	}

	return exitCode, fullOutput.String(), nil, false
}

// extractPlanJSON runs `terraform show -json tfplan` and returns the JSON output
func (a *TFAgentRunner) extractPlanJSON(tfBinary, terraformDir string, env []string) string {
	planFile := filepath.Join(terraformDir, "tfplan")
	if _, err := os.Stat(planFile); os.IsNotExist(err) {
		logger.Warnf("Plan file not found at %s, skipping JSON extraction", planFile)
		return ""
	}

	// #nosec G204 -- args are constructed from trusted sources
	showCmd := exec.CommandContext(context.Background(), tfBinary, "show", "-json", "tfplan") //nolint:gosec,noctx
	showCmd.Dir = terraformDir
	showCmd.Env = env

	showOut, err := showCmd.CombinedOutput()
	if err != nil {
		logger.Warnf("Failed to extract plan JSON: %v (output: %s)", err, string(showOut))
		return ""
	}

	logger.Infof("Extracted plan JSON (%d bytes)", len(showOut))
	return string(showOut)
}

// extractAndUploadState extracts the terraform state and uploads it to the server
func (a *TFAgentRunner) extractAndUploadState(tfBinary, terraformDir string, env []string, jobID string) {
	// Try to read the state file
	stateFile := filepath.Join(terraformDir, "terraform.tfstate")
	stateData, err := os.ReadFile(stateFile) //nolint:gosec // path constructed from controlled workspace dir
	if err != nil {
		logger.Debugf("No state file found at %s (normal for remote state): %v", stateFile, err)
		return
	}

	if len(stateData) == 0 {
		return
	}

	logger.Infof("Uploading state file (%d bytes) for job %s", len(stateData), jobID)

	// Upload state to the server
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	stateB64 := base64.StdEncoding.EncodeToString(stateData)
	payload := map[string]string{
		"runner_id": a.runnerID,
		"state":     stateB64,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		logger.Warnf("Failed to marshal state upload: %v", err)
		return
	}

	req, err := http.NewRequestWithContext(ctx, "POST", a.config.ServerURL+"/api/v2/runner/jobs/"+jobID+"/state", bytes.NewReader(body))
	if err != nil {
		logger.Warnf("Failed to create state upload request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+a.authToken())

	resp, err := a.client.Do(req) //nolint:gosec // G704: URL is the operator-configured server endpoint, not user-controlled
	if err != nil {
		logger.Warnf("Failed to upload state: %v", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusOK {
		logger.Infof("State file uploaded successfully for job %s", jobID)
	} else {
		logger.Warnf("State upload returned status %d for job %s", resp.StatusCode, jobID)
	}
}

// extractTarGzForAgent extracts a tar.gz archive to a directory
func extractTarGzForAgent(data []byte, destDir string) error {
	gzReader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer func() { _ = gzReader.Close() }()

	tarReader := tar.NewReader(gzReader)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("tar read error: %w", err)
		}

		target := filepath.Join(destDir, filepath.Clean(header.Name))
		// Ensure target is within destDir (prevent path traversal)
		if !strings.HasPrefix(target, filepath.Clean(destDir)+string(os.PathSeparator)) && target != filepath.Clean(destDir) {
			continue
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o750); err != nil {
				return fmt.Errorf("failed to create directory %s: %w", target, err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
				return fmt.Errorf("failed to create parent dir for %s: %w", target, err)
			}
			outFile, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(header.Mode)) //nolint:gosec // G304: target is validated to be within destDir above
			if err != nil {
				return fmt.Errorf("failed to create file %s: %w", target, err)
			}
			// AUD-073: cap per-file decompression at 100MB to match the non-agent runner
			// (main.go) and prevent a gzip bomb from exhausting a self-hosted agent's disk/memory.
			const maxDecompressedSize = 100 * 1024 * 1024 // 100MB
			if _, err := io.Copy(outFile, io.LimitReader(tarReader, maxDecompressedSize)); err != nil {
				_ = outFile.Close()
				return fmt.Errorf("failed to extract file %s: %w", target, err)
			}
			_ = outFile.Close()
		}
	}
	return nil
}

// replaceRemoteBackendForAgent replaces remote/cloud backend configs with local backend
// to prevent the self-hosted runner from creating nested remote runs.
// This uses brace-counting to properly remove the entire block (including body and closing brace).
func replaceRemoteBackendForAgent(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".tf") {
			continue
		}
		filePath := filepath.Join(dir, entry.Name())
		content, err := os.ReadFile(filePath) //nolint:gosec // G304: filePath is constructed from trusted directory listing
		if err != nil {
			continue
		}
		contentStr := string(content)
		modified := contentStr

		// Remove cloud { ... } blocks (used by TFC/TFE)
		modified = removeHCLBlock(modified, "cloud {")
		// Remove backend "remote" { ... } blocks
		modified = removeHCLBlock(modified, `backend "remote" {`)

		if modified != contentStr {
			_ = os.WriteFile(filePath, []byte(modified), 0o600) //nolint:gosec // G703: filePath is constructed from trusted directory listing via os.ReadDir
			logger.Infof("Replaced remote backend in %s", entry.Name())
		}
	}
}

// removeHCLBlock finds a block starting with the given opener (e.g. "cloud {" or `backend "remote" {`)
// and removes the entire block including all nested braces and the closing brace.
// This handles nested blocks correctly via brace counting.
func removeHCLBlock(content, opener string) string {
	for {
		idx := strings.Index(content, opener)
		if idx == -1 {
			return content
		}

		// Find the start of the block opening (include any leading whitespace on the same line)
		blockStart := idx
		for blockStart > 0 && content[blockStart-1] != '\n' {
			blockStart--
		}

		// Count braces to find the matching closing brace
		braceCount := 0
		pos := idx
		foundOpen := false
		for pos < len(content) {
			if content[pos] == '{' {
				braceCount++
				foundOpen = true
			} else if content[pos] == '}' {
				braceCount--
				if foundOpen && braceCount == 0 {
					// Found the matching closing brace
					blockEnd := pos + 1
					// Include trailing newline if present
					if blockEnd < len(content) && content[blockEnd] == '\n' {
						blockEnd++
					}
					// Replace block with a comment
					replacement := "  # Backend removed by StackWeaver agent runner\n  backend \"local\" {}\n"
					content = content[:blockStart] + replacement + content[blockEnd:]
					break
				}
			}
			pos++
		}

		if !foundOpen || braceCount != 0 {
			// Malformed block - bail to avoid infinite loop
			return content
		}
	}
}

// tfStreamWriter implements io.Writer to stream output to the server
type tfStreamWriter struct {
	agent    *TFAgentRunner
	jobID    string
	phase    string // "plan" or "apply"
	buffer   *bytes.Buffer
	lastSend time.Time
}

func (w *tfStreamWriter) Write(p []byte) (int, error) {
	n, err := w.buffer.Write(p)

	// Send output every second or when buffer exceeds 4KB
	if time.Since(w.lastSend) > time.Second || w.buffer.Len() > 4096 {
		w.flush()
	}

	return n, err
}

func (w *tfStreamWriter) flush() {
	if w.buffer.Len() == 0 {
		return
	}

	output := w.buffer.String()
	w.buffer.Reset()
	w.lastSend = time.Now()

	// AUD-028: send synchronously, not in a fire-and-forget goroutine. The server appends each
	// chunk to the phase log via read-modify-write on object storage, so overlapping goroutines
	// raced (lost updates) and could arrive out of order. Serializing the sends here - one flush
	// completes before the next - makes a single agent the sole, ordered writer for its run.
	w.agent.sendJobOutput(w.jobID, output, w.phase)
}

// sendJobOutput sends job output to the server
func (a *TFAgentRunner) sendJobOutput(jobID, output, stream string) {
	payload := map[string]string{
		"runner_id": a.runnerID,
		"output":    output,
		"stream":    stream,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		logger.Warnf("Failed to marshal job output: %v", err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", a.config.ServerURL+"/api/v2/runner/jobs/"+jobID+"/output", bytes.NewReader(body))
	if err != nil {
		logger.Warnf("Failed to create output request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+a.authToken())

	resp, err := a.client.Do(req) //nolint:gosec // G704: URL is the operator-configured server endpoint, not user-controlled
	if err != nil {
		logger.Warnf("Failed to send job output: %v", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()
}

// notifyJobStart notifies the server that a job has started
func (a *TFAgentRunner) notifyJobStart(jobID string) error {
	payload := map[string]string{
		"runner_id": a.runnerID,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", a.config.ServerURL+"/api/v2/runner/jobs/"+jobID+"/start", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+a.authToken())

	resp, err := a.client.Do(req) //nolint:gosec // G704: URL is the operator-configured server endpoint, not user-controlled
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("job start notification failed: status %d", resp.StatusCode)
	}

	return nil
}

// notifyJobComplete notifies the server that a job has completed
func (a *TFAgentRunner) notifyJobComplete(jobID, status, output string) {
	payload := map[string]interface{}{
		"runner_id": a.runnerID,
		"status":    status,
		"output":    output,
	}
	// For failed jobs, also send the output as error_message so the server stores it
	if status == "failed" && output != "" {
		payload["error_message"] = output
	}

	// If we have plan JSON, parse resource counts and include them
	if a.planJSONCache != "" && status == "completed" {
		planMeta := parsePlanJSON(a.planJSONCache)
		payload["resource_additions"] = planMeta.Additions
		payload["resource_changes"] = planMeta.Changes
		payload["resource_destructions"] = planMeta.Destructions
		payload["output_changes"] = planMeta.OutputChanges
		payload["has_changes"] = planMeta.HasChanges
		payload["plan_json"] = a.planJSONCache
		logger.Infof("Plan metadata: additions=%d, changes=%d, destructions=%d, outputChanges=%d, hasChanges=%v",
			planMeta.Additions, planMeta.Changes, planMeta.Destructions, planMeta.OutputChanges, planMeta.HasChanges)
	}

	body, err := json.Marshal(payload)
	if err != nil {
		logger.Warnf("Failed to marshal job complete: %v", err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", a.config.ServerURL+"/api/v2/runner/jobs/"+jobID+"/complete", bytes.NewReader(body))
	if err != nil {
		logger.Warnf("Failed to create complete request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+a.authToken())

	resp, err := a.client.Do(req) //nolint:gosec // G704: URL is the operator-configured server endpoint, not user-controlled
	if err != nil {
		logger.Warnf("Failed to notify job complete: %v", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()
}

// planMetadata holds parsed resource counts from a plan JSON
type planMetadata struct {
	Additions     int
	Changes       int
	Destructions  int
	OutputChanges int
	HasChanges    bool
}

// parsePlanJSON extracts resource and output change counts from terraform show -json output
func parsePlanJSON(planJSON string) planMetadata {
	var plan map[string]interface{}
	if err := json.Unmarshal([]byte(planJSON), &plan); err != nil {
		logger.Warnf("Failed to parse plan JSON: %v", err)
		return planMetadata{}
	}

	meta := planMetadata{}

	// Count resource changes
	if resourceChanges, ok := plan["resource_changes"].([]interface{}); ok {
		for _, rc := range resourceChanges {
			change, ok := rc.(map[string]interface{})
			if !ok {
				continue
			}
			changeDetail, ok := change["change"].(map[string]interface{})
			if !ok {
				continue
			}
			actions, ok := changeDetail["actions"].([]interface{})
			if !ok {
				continue
			}
			for _, action := range actions {
				actionStr, ok := action.(string)
				if !ok {
					continue
				}
				switch actionStr {
				case "create":
					meta.Additions++
				case "update":
					meta.Changes++
				case "delete":
					meta.Destructions++
				}
			}
		}
	}

	// Count output changes (output_changes is a map of name -> change object)
	if outputChanges, ok := plan["output_changes"].(map[string]interface{}); ok {
		for _, oc := range outputChanges {
			changeMap, ok := oc.(map[string]interface{})
			if !ok {
				continue
			}
			actions, ok := changeMap["actions"].([]interface{})
			if !ok {
				continue
			}
			for _, a := range actions {
				if actionStr, ok := a.(string); ok && actionStr != "no-op" {
					meta.OutputChanges++
					break
				}
			}
		}
	}

	meta.HasChanges = meta.Additions > 0 || meta.Changes > 0 || meta.Destructions > 0 || meta.OutputChanges > 0
	return meta
}

// deregister deregisters the runner from the server
func (a *TFAgentRunner) deregister() {
	payload := map[string]string{
		"runner_id": a.runnerID,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		logger.Warnf("Failed to marshal deregister: %v", err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", a.config.ServerURL+"/api/v2/runner/deregister", bytes.NewReader(body))
	if err != nil {
		logger.Warnf("Failed to create deregister request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+a.authToken())

	resp, err := a.client.Do(req) //nolint:gosec // G704: URL is the operator-configured server endpoint, not user-controlled
	if err != nil {
		logger.Warnf("Failed to deregister: %v", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()
}

// Helper functions

func getHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return hostname
}

// resolveTofuBinary finds the exact OpenTofu binary for the requested version, downloading it if
// needed. Resolution and download live in core/tofu so this agent path and the library path in
// core/plugins/opentofu share one implementation - historically this file carried a near-duplicate
// downloader that never verified checksums (AUD-058 hardened only the other copy).
//
// The version must be set on the workspace or org before a run is created.
func resolveTofuBinary(requestedVersion string) string {
	if requestedVersion == "" {
		logger.Errorf("FATAL: no opentofu version specified -- version must be set on workspace or organization")
		return "tofu-version-not-set" // will fail with a clear error
	}

	path, err := tofu.ResolveBinary(requestedVersion)
	if err != nil {
		logger.Errorf("FATAL: cannot get opentofu %s: %v", requestedVersion, err)
		// Return the canonical versioned path so the command fails with "binary not found"
		// rather than silently executing a different version.
		return tofu.VersionedPath(requestedVersion)
	}
	return path
}

// getTofuVersion reports the version of the tofu binary on PATH, for runner registration.
// OpenTofu keeps Terraform's `version -json` schema, including the "terraform_version" key.
func getTofuVersion() string {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, tofu.BinaryName, "version", "-json") //nolint:gosec // G204: BinaryName is a package constant, args are literals
	output, err := cmd.Output()
	if err != nil {
		// Try without the -json flag
		cmd = exec.CommandContext(ctx, tofu.BinaryName, "version") //nolint:gosec // G204: BinaryName is a package constant, args are literals
		output, err = cmd.Output()
		if err != nil {
			return "unknown"
		}
		// Parse the first line: "OpenTofu vX.Y.Z"
		lines := strings.Split(string(output), "\n")
		if len(lines) > 0 {
			parts := strings.Fields(lines[0])
			if len(parts) >= 2 {
				return strings.TrimPrefix(parts[1], "v")
			}
		}
		return "unknown"
	}

	var versionInfo struct {
		TerraformVersion string `json:"terraform_version"`
	}
	if err := json.Unmarshal(output, &versionInfo); err != nil {
		return "unknown"
	}
	return versionInfo.TerraformVersion
}
