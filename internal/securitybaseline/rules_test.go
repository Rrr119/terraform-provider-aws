// Copyright IBM Corp. 2026
// SPDX-License-Identifier: MPL-2.0

package securitybaseline

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestS3BucketPublicACLRule(t *testing.T) {
	t.Parallel()

	rule := S3BucketPublicACLRule{}

	testCases := map[string]struct {
		resource Resource
		finding  bool
	}{
		"public read ACL": {
			resource: Resource{Type: "aws_s3_bucket", Values: map[string]any{"acl": "public-read"}},
			finding:  true,
		},
		"private ACL": {
			resource: Resource{Type: "aws_s3_bucket", Values: map[string]any{"acl": "private"}},
			finding:  false,
		},
		"unrelated resource type": {
			resource: Resource{Type: "aws_s3_bucket_policy", Values: map[string]any{"acl": "public-read"}},
			finding:  false,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			findings := rule.Check(testCase.resource)
			if (len(findings) > 0) != testCase.finding {
				t.Fatalf("expected finding=%t, got %d findings", testCase.finding, len(findings))
			}
		})
	}
}

func TestS3BucketPublicPolicyRule(t *testing.T) {
	t.Parallel()

	rule := S3BucketPublicPolicyRule{}

	scopedPolicy := `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:role/app"},"Action":"s3:GetObject"}]}`
	rootWildcard := `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"s3:GetObject"}]}`
	denyWildcard := `{"Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:GetObject"}]}`

	testCases := map[string]struct {
		policy  any
		finding bool
	}{
		"wildcard principal string": {
			policy:  `{"Statement":[{"Effect":"Allow","Principal":"*"}]}`,
			finding: true,
		},
		"wildcard principal map": {
			policy:  rootWildcard,
			finding: true,
		},
		"scoped account principal": {
			policy:  scopedPolicy,
			finding: false,
		},
		"wildcard with deny effect": {
			policy:  denyWildcard,
			finding: false,
		},
		"decoded policy document": {
			policy: map[string]any{
				"Statement": []any{
					map[string]any{"Effect": "Allow", "Principal": "*"},
				},
			},
			finding: true,
		},
		"malformed policy": {
			policy:  "not-json",
			finding: false,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			resource := Resource{
				Type:   "aws_s3_bucket_policy",
				Values: map[string]any{"policy": testCase.policy},
			}

			findings := rule.Check(resource)
			if (len(findings) > 0) != testCase.finding {
				t.Fatalf("expected finding=%t, got %d findings", testCase.finding, len(findings))
			}
		})
	}
}

func TestS3BucketPublicAccessBlockRule(t *testing.T) {
	t.Parallel()

	rule := S3BucketPublicAccessBlockRule{}
	enabledBlock := map[string]any{
		"block_public_acls":       true,
		"block_public_policy":     true,
		"ignore_public_acls":      true,
		"restrict_public_buckets": true,
	}

	testCases := map[string]struct {
		values   map[string]any
		severity Severity
	}{
		"missing block": {
			values:   map[string]any{},
			severity: SeverityMedium,
		},
		"partially disabled block": {
			values: map[string]any{
				"public_access_block": []any{
					map[string]any{"block_public_policy": false},
				},
			},
			severity: SeverityMedium,
		},
		"fully enabled block": {
			values:   map[string]any{"public_access_block": []any{enabledBlock}},
			severity: "",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			findings := rule.Check(Resource{Type: "aws_s3_bucket", Values: testCase.values})

			if testCase.severity == "" {
				if len(findings) != 0 {
					t.Fatalf("expected no findings, got %d", len(findings))
				}

				return
			}

			if len(findings) != 1 || findings[0].Severity != testCase.severity {
				t.Fatalf("expected one %s finding, got %#v", testCase.severity, findings)
			}
		})
	}
}

func TestSecurityGroupOpenIngressRule(t *testing.T) {
	t.Parallel()

	rule := SecurityGroupOpenIngressRule{}

	testCases := map[string]struct {
		resource Resource
		finding  bool
	}{
		"SSH open to the world": {
			resource: Resource{
				Type: "aws_security_group",
				Values: map[string]any{
					"ingress": []any{
						map[string]any{"from_port": 22, "to_port": 22, "protocol": "tcp", "cidr_blocks": []any{"0.0.0.0/0"}},
					},
				},
			},
			finding: true,
		},
		"SSH restricted to private CIDR": {
			resource: Resource{
				Type: "aws_security_group",
				Values: map[string]any{
					"ingress": []any{
						map[string]any{"from_port": 22, "to_port": 22, "protocol": "tcp", "cidr_blocks": []any{"10.0.0.0/8"}},
					},
				},
			},
			finding: false,
		},
		"HTTPS open to the world": {
			resource: Resource{
				Type: "aws_security_group",
				Values: map[string]any{
					"ingress": []any{
						map[string]any{"from_port": 443, "to_port": 443, "protocol": "tcp", "cidr_blocks": []any{"0.0.0.0/0"}},
					},
				},
			},
			finding: false,
		},
		"all protocols open to the world": {
			resource: Resource{
				Type: "aws_vpc_security_group_ingress_rule",
				Values: map[string]any{
					"ip_protocol": "-1",
					"cidr_ipv4":   "0.0.0.0/0",
				},
			},
			finding: true,
		},
		"standalone MySQL rule": {
			resource: Resource{
				Type: "aws_security_group_rule",
				Values: map[string]any{
					"type":        "ingress",
					"protocol":    "tcp",
					"from_port":   3306,
					"to_port":     3306,
					"cidr_blocks": []any{"::/0"},
				},
			},
			finding: true,
		},
		"egress rule is ignored": {
			resource: Resource{
				Type: "aws_security_group_rule",
				Values: map[string]any{
					"type":        "egress",
					"protocol":    "-1",
					"cidr_blocks": []any{"0.0.0.0/0"},
				},
			},
			finding: false,
		},
		"IPv6 zero prefix": {
			resource: Resource{
				Type: "aws_vpc_security_group_ingress_rule",
				Values: map[string]any{
					"ip_protocol": "tcp",
					"from_port":   5432,
					"to_port":     5432,
					"cidr_ipv6":   "::/0",
				},
			},
			finding: true,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			findings := rule.Check(testCase.resource)
			if (len(findings) > 0) != testCase.finding {
				t.Fatalf("expected finding=%t, got %#v", testCase.finding, findings)
			}
		})
	}
}

func TestEvaluateFindingShape(t *testing.T) {
	t.Parallel()

	resources := []Resource{{
		Address: "aws_s3_bucket.example",
		Type:    "aws_s3_bucket",
		Values:  map[string]any{"acl": "public-read-write"},
	}}

	findings := Evaluate(resources, nil)

	if len(findings) != 2 {
		t.Fatalf("expected ACL and missing access block findings, got %#v", findings)
	}

	for _, finding := range findings {
		if finding.Address != "aws_s3_bucket.example" || finding.Message == "" {
			t.Fatalf("finding missing address or message: %#v", finding)
		}
	}

	ruleIDs := []string{findings[0].RuleID, findings[1].RuleID}
	if diff := cmp.Diff([]string{"S301", "S303"}, ruleIDs); diff != "" {
		t.Fatalf("unexpected rule IDs (-expected +got):\n%s", diff)
	}
}
