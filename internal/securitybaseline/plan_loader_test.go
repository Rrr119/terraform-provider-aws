// Copyright IBM Corp. 2026
// SPDX-License-Identifier: MPL-2.0

package securitybaseline

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

const samplePlan = `{
  "format_version": "1.2",
  "terraform_version": "1.9.0",
  "resource_changes": [
    {
      "address": "aws_security_group.created",
      "mode": "managed",
      "type": "aws_security_group",
      "name": "created",
      "provider_name": "registry.terraform.io/hashicorp/aws",
      "change": {
        "actions": ["create"],
        "before": null,
        "after": {
          "ingress": [
            {
              "from_port": 22,
              "to_port": 22,
              "protocol": "tcp",
              "cidr_blocks": ["0.0.0.0/0"]
            }
          ]
        },
        "after_unknown": {}
      }
    },
    {
      "address": "aws_s3_bucket.updated",
      "mode": "managed",
      "type": "aws_s3_bucket",
      "name": "updated",
      "provider_name": "registry.terraform.io/hashicorp/aws",
      "change": {
        "actions": ["update"],
        "before": {"acl": "private"},
        "after": {"acl": "public-read"},
        "after_unknown": {}
      }
    },
    {
      "address": "aws_s3_bucket.deleted",
      "mode": "managed",
      "type": "aws_s3_bucket",
      "name": "deleted",
      "provider_name": "registry.terraform.io/hashicorp/aws",
      "change": {
        "actions": ["delete"],
        "before": {"acl": "public-read"},
        "after": null,
        "after_unknown": {}
      }
    },
    {
      "address": "data.aws_caller_identity.current",
      "mode": "data",
      "type": "aws_caller_identity",
      "name": "current",
      "provider_name": "registry.terraform.io/hashicorp/aws",
      "change": {
        "actions": ["read"],
        "before": null,
        "after": {"account_id": "123456789012"},
        "after_unknown": {}
      }
    }
  ]
}`

func TestLoadPlanChecksCreateAndUpdate(t *testing.T) {
	t.Parallel()

	resources, err := LoadPlan([]byte(samplePlan))
	if err != nil {
		t.Fatalf("loading plan: %s", err)
	}

	addresses := make([]string, len(resources))

	for index, resource := range resources {
		addresses[index] = resource.Address
	}

	if diff := cmp.Diff([]string{"aws_security_group.created", "aws_s3_bucket.updated"}, addresses); diff != "" {
		t.Fatalf("unexpected planned resources (-expected +got):\n%s", diff)
	}

	findings := Evaluate(resources, nil)
	ruleIDs := make([]string, 0, len(findings))

	for _, finding := range findings {
		ruleIDs = append(ruleIDs, finding.RuleID)
	}

	if diff := cmp.Diff([]string{"SG01", "S301", "S303"}, ruleIDs); diff != "" {
		t.Fatalf("unexpected plan findings (-expected +got):\n%s", diff)
	}
}

func TestLoadPlanNormalizesJSONNumbers(t *testing.T) {
	t.Parallel()

	const plan = `{
	  "format_version": "1.2",
	  "resource_changes": [
	    {
	      "address": "aws_security_group_rule.redis",
	      "mode": "managed",
	      "type": "aws_security_group_rule",
	      "name": "redis",
	      "change": {
	        "actions": ["create"],
	        "after": {
	          "type": "ingress",
	          "protocol": "tcp",
	          "from_port": 6379,
	          "to_port": 6379,
	          "cidr_blocks": ["0.0.0.0/0"]
	        }
	      }
	    }
	  ]
}`

	resources, err := LoadPlan([]byte(plan))
	if err != nil {
		t.Fatalf("loading plan: %s", err)
	}

	findings := Evaluate(resources, nil)
	if len(findings) != 1 || findings[0].RuleID != "SG01" {
		t.Fatalf("expected one SG01 finding, got %#v", findings)
	}
}

func TestLoadPlanRejectsInvalidJSON(t *testing.T) {
	t.Parallel()

	if _, err := LoadPlan([]byte("{")); err == nil {
		t.Fatal("expected an error for malformed plan JSON")
	}
}
