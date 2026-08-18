// Copyright (c) 2026 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package main

import (
	"strings"
	"testing"
)

// TestReplaceRemoteBackendInContent covers AUD-080: the platform runner must strip both TFC/TFE
// `cloud {}` blocks and `backend "remote"` blocks (it previously handled only the latter, on a
// fixed four-filename list, drifting from the agent runner).
func TestReplaceRemoteBackendInContent(t *testing.T) {
	cases := []struct {
		name          string
		in            string
		wantContains  []string
		wantAbsent    []string
		wantUnchanged bool
	}{
		{
			name:         "cloud block removed",
			in:           "terraform {\n  cloud {\n    organization = \"acme\"\n    workspaces { name = \"prod\" }\n  }\n}\n",
			wantAbsent:   []string{"cloud {", "organization = \"acme\""},
			wantContains: []string{"terraform {"},
		},
		{
			name:         "remote backend rewritten to local",
			in:           "terraform {\n  backend \"remote\" {\n    organization = \"acme\"\n    workspaces { name = \"prod\" }\n  }\n}\n",
			wantAbsent:   []string{"backend \"remote\""},
			wantContains: []string{"backend \"local\"", "terraform.tfstate"},
		},
		{
			name:          "plain config untouched",
			in:            "resource \"null_resource\" \"a\" {}\n",
			wantUnchanged: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := replaceRemoteBackendInContent(tc.in)
			if tc.wantUnchanged && got != tc.in {
				t.Fatalf("expected unchanged, got:\n%s", got)
			}
			for _, s := range tc.wantContains {
				if !strings.Contains(got, s) {
					t.Errorf("expected output to contain %q, got:\n%s", s, got)
				}
			}
			for _, s := range tc.wantAbsent {
				if strings.Contains(got, s) {
					t.Errorf("expected output to NOT contain %q, got:\n%s", s, got)
				}
			}
		})
	}
}
