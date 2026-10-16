// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// What a self-hosted OpenTofu agent hands the processes it starts for a run (#932). The agent's
// environment holds its runner token (STACKWEAVER_TOKEN), and whatever else the host it runs on
// carries; a run's configuration executes code the run's author controls (providers, the external
// data source, local-exec). The defect this test was written against: tofu init, plan, apply and
// show were started with the agent's whole environment.
//
// The tofu binary is a shell script installed where core/tofu looks for a versioned binary, so the
// real runTerraform path resolves and runs it. It records what it was handed per subcommand.

package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var agentSecrets = map[string]string{
	"STACKWEAVER_TOKEN":        "placeholder-agent-token",
	"DATABASE_PASSWORD":        "placeholder-database-password",
	"ENCRYPTION_KEY":           "placeholder-encryption-key",
	"OIDC_SIGNING_KEY":         "placeholder-signing-key",
	"SOME_FUTURE_PLATFORM_KEY": "placeholder-future-secret",
}

func TestRunTerraform_UserCodeCannotReadAgentSecrets(t *testing.T) {
	const version = "0.0.0-envtest" // never installed in /usr/local/bin, so the HOME fallback is used
	home, record := t.TempDir(), t.TempDir()
	t.Setenv("HOME", home)
	for name, value := range agentSecrets {
		t.Setenv(name, value)
	}
	script := `#!/bin/sh
env > "` + record + `/$1.env"
echo "user code read: [$STACKWEAVER_TOKEN][$DATABASE_PASSWORD][$ENCRYPTION_KEY][$OIDC_SIGNING_KEY]"
if [ "$1" = plan ]; then : > tfplan; fi
if [ "$1" = show ]; then echo '{}'; fi
exit 0
`
	versions := filepath.Join(home, ".tofu-versions")
	if err := os.MkdirAll(versions, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(versions, "tofu-"+version), []byte(script), 0o700); err != nil { //nolint:gosec // G306: the stand-in must be executable
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/status") {
			_, _ = w.Write([]byte(`{"status":"running"}`))
		}
	}))
	t.Cleanup(srv.Close)
	agent := &TFAgentRunner{
		config:      TFAgentConfig{ServerURL: srv.URL, Token: "placeholder-registration-key", PollInterval: time.Second},
		runnerToken: "placeholder-runner-key",
		client:      srv.Client(),
		shutdown:    make(chan struct{}),
	}

	exitCode, output, err, _ := agent.runTerraform(
		TFPendingJob{JobID: "envtest", RunType: "plan"},
		&TFJobArtifacts{TofuVersion: version, EnvironmentVars: map[string]string{"TF_VAR_region": "eu-west-1"}},
	)
	if err != nil || exitCode != 0 {
		t.Fatalf("runTerraform = %d, %v (output %q)", exitCode, err, output)
	}

	check := func(where, text string) {
		t.Helper()
		for name, value := range agentSecrets {
			if strings.Contains(text, name+"=") || strings.Contains(text, value) {
				t.Errorf("%s: user code could read the agent's %s", where, name)
			}
		}
	}
	check("run output", output)
	for _, sub := range []string{"init", "plan", "show"} {
		data, err := os.ReadFile(filepath.Join(record, sub+".env")) //nolint:gosec // G304: a file this test's own stand-in wrote
		if err != nil {
			t.Fatalf("tofu %s recorded no environment: %v", sub, err)
		}
		check("tofu "+sub+" environment", string(data))
		if !strings.Contains(string(data), "TF_VAR_region=eu-west-1\n") {
			t.Errorf("tofu %s was not handed the run's own TF_VAR_region", sub)
		}
	}
}
