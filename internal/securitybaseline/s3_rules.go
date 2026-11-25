// Copyright IBM Corp. 2026
// SPDX-License-Identifier: MPL-2.0

package securitybaseline

import "strings"

const s3BucketType = "aws_s3_bucket"

// S3BucketPublicACLRule flags aws_s3_bucket resources whose ACL grants public
// access. Bucket ACLs are deprecated in favor of public access blocks, but
// configurations that still set a public ACL expose bucket contents.
type S3BucketPublicACLRule struct{}

// ID returns the rule identifier.
func (S3BucketPublicACLRule) ID() string {
	return "S301"
}

// Check returns a finding when the bucket uses a public canned ACL.
func (rule S3BucketPublicACLRule) Check(resource Resource) []Finding {
	if resource.Type != s3BucketType {
		return nil
	}

	switch stringValue(resource.Values, "acl") {
	case "public-read", "public-read-write", "website":
	default:
		return nil
	}

	return []Finding{{
		RuleID:   rule.ID(),
		Severity: SeverityHigh,
		Address:  resource.Address,
		Message:  "S3 bucket uses a public ACL that grants access to all AWS users",
	}}
}

// S3BucketPublicPolicyRule flags aws_s3_bucket_policy resources whose policy
// statement allows any principal. A wildcard principal with an Allow effect
// makes the bucket reachable by unauthenticated callers.
type S3BucketPublicPolicyRule struct{}

// ID returns the rule identifier.
func (S3BucketPublicPolicyRule) ID() string {
	return "S302"
}

// Check returns a finding when the bucket policy contains a public Allow.
func (rule S3BucketPublicPolicyRule) Check(resource Resource) []Finding {
	if resource.Type != "aws_s3_bucket_policy" {
		return nil
	}

	for _, statement := range jsonStatements(resource.Values["policy"]) {
		if statementAllows(statement) && allowsAnyPrincipal(statement) {
			return []Finding{{
				RuleID:   rule.ID(),
				Severity: SeverityHigh,
				Address:  resource.Address,
				Message:  "S3 bucket policy allows a wildcard principal",
			}}
		}
	}

	return nil
}

// S3BucketPublicAccessBlockRule flags aws_s3_bucket resources that do not
// enable all four public access block controls. The AWS security baseline
// expects every bucket to block public access; an explicit false or a missing
// block leaves the control disabled.
type S3BucketPublicAccessBlockRule struct{}

// ID returns the rule identifier.
func (S3BucketPublicAccessBlockRule) ID() string {
	return "S303"
}

var publicAccessBlockAttributes = []struct {
	name  string
	label string
}{
	{name: "block_public_acls", label: "BlockPublicAcls"},
	{name: "block_public_policy", label: "BlockPublicPolicy"},
	{name: "ignore_public_acls", label: "IgnorePublicAcls"},
	{name: "restrict_public_buckets", label: "RestrictPublicBuckets"},
}

// Check returns a finding naming each public access control left disabled.
func (rule S3BucketPublicAccessBlockRule) Check(resource Resource) []Finding {
	if resource.Type != s3BucketType {
		return nil
	}

	blocks := nestedBlocks(resource.Values, "public_access_block")
	if len(blocks) == 0 {
		return []Finding{{
			RuleID:   rule.ID(),
			Severity: SeverityMedium,
			Address:  resource.Address,
			Message:  "S3 bucket has no public access block configuration",
		}}
	}

	var disabled []string

	for _, block := range blocks {
		for _, attribute := range publicAccessBlockAttributes {
			enabled, present := boolValue(block, attribute.name)
			if !present || !enabled {
				disabled = append(disabled, attribute.label)
			}
		}
	}

	if len(disabled) == 0 {
		return nil
	}

	return []Finding{{
		RuleID:   rule.ID(),
		Severity: SeverityMedium,
		Address:  resource.Address,
		Message:  "S3 bucket public access block disables: " + strings.Join(disabled, ", "),
	}}
}
