// Copyright IBM Corp. 2026
// SPDX-License-Identifier: MPL-2.0

package securitybaseline

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestLoadConfigEvaluateTestdata(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		expectedRuleIDs []string
	}{
		"01_s3_public_acl.tf":           {expectedRuleIDs: []string{"S301", "S303"}},
		"02_s3_public_policy.tf":        {expectedRuleIDs: []string{"S303", "S302"}},
		"03_s3_missing_access_block.tf": {expectedRuleIDs: []string{"S303"}},
		"04_s3_weak_access_block.tf":    {expectedRuleIDs: []string{"S303"}},
		"05_s3_secure.tf":               {expectedRuleIDs: nil},
		"06_sg_ssh_world.tf":            {expectedRuleIDs: []string{"SG01"}},
		"07_sg_rdp_world.tf":            {expectedRuleIDs: []string{"SG01"}},
		"08_sg_standalone_rule.tf":      {expectedRuleIDs: []string{"SG01"}},
		"09_sg_all_protocols.tf":        {expectedRuleIDs: []string{"SG01"}},
		"10_sg_secure.tf":               {expectedRuleIDs: nil},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			src, err := os.ReadFile(filepath.Join("testdata", name))
			if err != nil {
				t.Fatalf("reading test configuration: %s", err)
			}

			resources, diags := LoadConfig(name, src)
			if diags.HasErrors() {
				t.Fatalf("parsing configuration: %s", diags.Error())
			}

			findings := Evaluate(resources, nil)
			ruleIDs := make([]string, 0, len(findings))

			for _, finding := range findings {
				ruleIDs = append(ruleIDs, finding.RuleID)
			}

			if len(testCase.expectedRuleIDs) == 0 {
				testCase.expectedRuleIDs = []string{}
			}

			if diff := cmp.Diff(testCase.expectedRuleIDs, ruleIDs); diff != "" {
				t.Fatalf("unexpected finding rule IDs (-expected +got):\n%s", diff)
			}
		})
	}
}

func TestLoadConfigReturnsTenConfigurations(t *testing.T) {
	t.Parallel()

	entries, err := os.ReadDir("testdata")
	if err != nil {
		t.Fatalf("reading testdata directory: %s", err)
	}

	count := 0

	for _, entry := range entries {
		if filepath.Ext(entry.Name()) == ".tf" {
			count++
		}
	}

	if count != 10 {
		t.Fatalf("expected 10 Terraform configurations, got %d", count)
	}
}

func TestLoadConfigInvalidSyntax(t *testing.T) {
	t.Parallel()

	_, diags := LoadConfig("invalid.tf", []byte("resource \"aws_s3_bucket\" {\n"))
	if !diags.HasErrors() {
		t.Fatal("expected syntax diagnostics for an incomplete resource block")
	}
}
