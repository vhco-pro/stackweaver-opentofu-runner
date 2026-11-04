// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Command runner is the OpenTofu runner: a launcher that registers with its pool (or as a hosted
// launcher), holds one heartbeat and places an executor for each job it claims (#933, D3), and the
// `executor` subcommand that runs one job with a job token in a container or pod (D1, D2). It holds
// no database, object storage, Redis or platform secret.
package main

import (
	"context"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/michielvha/logger"
	"github.com/michielvha/stackweaver/backend/internal/executor"
	"github.com/michielvha/stackweaver/backend/internal/executor/syncexec"
	"github.com/michielvha/stackweaver/backend/internal/executor/tofuexec"
	"github.com/michielvha/stackweaver/backend/internal/launcher"
	"github.com/michielvha/stackweaver/backend/internal/launcher/driver"
	"github.com/michielvha/stackweaver/core/runnercontract"
	"github.com/michielvha/stackweaver/core/security/runenv"
)

func main() {
	// Started by git as a sync's askpass helper (#933, D2): answer one prompt and exit, before
	// anything else runs.
	if syncexec.IsAskpass() {
		os.Exit(syncexec.AskpassMain(os.Args[1:]))
	}
	logger.Init(os.Getenv("LOG_LEVEL"))

	// A job runs as this process's user; without this it could read the launcher's token from its
	// /proc environ (#936).
	if err := runenv.DenySameUserInspection(); err != nil {
		logger.Fatalf("Refusing to start: %v", err)
	}

	// `runner executor` runs exactly one job with a job token (#933, D1): what a launcher's
	// container and Kubernetes drivers start.
	if len(os.Args) > 1 && os.Args[1] == "executor" {
		os.Exit(runExecutor())
	}
	// `<binary> healthcheck` is the container healthcheck: the launcher's /readyz, with nothing
	// but this binary in the image (AC75).
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(launcher.Healthcheck(context.Background(), os.Getenv))
	}

	self, err := os.Executable()
	if err != nil {
		logger.Fatalf("Locating this binary: %v", err)
	}
	os.Exit(launcher.Main(launcher.Binary{
		Engine:       "tofu",
		Executor:     runInProcess,
		ExecutorPath: self,
		Version:      runnerVersion(),
		TofuVersion:  tofuexec.TofuVersion(),
	}))
}

// runnerVersion is the release this binary reports at registration.
func runnerVersion() string {
	if v := os.Getenv("STACKWEAVER_VERSION"); v != "" {
		return v
	}
	return "dev"
}

// runExecutor runs the `executor` subcommand: one job, from the invocation a driver set.
func runExecutor() int {
	inv, err := executor.InvocationFromEnv()
	if err != nil {
		// Without an invocation there is no job to report on: the launcher reports it.
		logger.Errorf("executor: %v", err)
		return executor.ExitUnreported
	}
	// SIGTERM from a driver stopping the placement cancels the job, which the executor reports.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	return execute(ctx, driver.Invocation{ServerURL: inv.ServerURL, JobID: inv.JobID, Token: inv.Token, RunType: inv.RunType, RunnerID: inv.RunnerID, CacheDir: inv.CacheDir})
}

// runInProcess is the in-process driver's executor: the same job, in the launcher's process.
func runInProcess(ctx context.Context, inv driver.Invocation) int { return execute(ctx, inv) }

// execute runs one job: a sync work item in the sync executor, every other job in the OpenTofu
// executor.
func execute(ctx context.Context, inv driver.Invocation) int {
	client := executor.NewClient(inv.ServerURL, inv.Token, inv.RunnerID)
	client.SetPlacement(inv.Placement)
	client.SetLimitsReport(inv.LimitsReport)
	if strings.HasPrefix(inv.JobID, runnercontract.WorkItemPrefix) {
		if !client.Preflight(ctx, inv.JobID, "stdout") {
			return client.ExitCode("failed")
		}
		return client.ExitCode(syncexec.Execute(ctx, client, inv.JobID, syncexec.Options{}).Status)
	}
	stream := "plan"
	if strings.HasPrefix(inv.RunType, "apply") {
		stream = "apply"
	}
	if !client.Preflight(ctx, inv.JobID, stream) {
		return client.ExitCode("failed")
	}
	res := tofuexec.Execute(ctx, client, tofuexec.Job{ID: inv.JobID, RunType: inv.RunType}, tofuexec.Options{CacheDir: inv.CacheDir})
	return client.ExitCode(res.Status)
}
