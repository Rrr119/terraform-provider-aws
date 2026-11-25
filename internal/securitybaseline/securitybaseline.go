// Copyright IBM Corp. 2026
// SPDX-License-Identifier: MPL-2.0

// Package securitybaseline evaluates Terraform configurations and plan files
// against a small set of AWS security baseline rules.
//
// The package is framework-agnostic: loaders turn HCL configuration or a
// Terraform JSON plan into a common Resource representation, and the rules
// operate on that representation. This keeps the checks compatible with the
// existing Terraform plan flow without coupling them to any single resource
// implementation or plugin framework.
package securitybaseline

// Severity describes how strongly a finding violates the baseline.
type Severity string

const (
	// SeverityHigh indicates a setting that directly exposes a resource.
	SeverityHigh Severity = "high"
	// SeverityMedium indicates a setting that weakens a protective control.
	SeverityMedium Severity = "medium"
)

// Resource is the framework-agnostic view of a planned or configured resource.
// Values contain the decoded HCL/JSON values: strings, ints, bools,
// []any, map[string]any, and nested resource blocks. Nested blocks are stored
// as a []map[string]any entry under the block type name.
type Resource struct {
	// Address is the Terraform resource address, for example
	// aws_s3_bucket.example.
	Address string
	// Type is the resource type, for example aws_security_group.
	Type string
	// Values holds the resource attributes and nested blocks.
	Values map[string]any
}

// Finding is a single baseline violation.
type Finding struct {
	// RuleID identifies the rule that produced the finding.
	RuleID string
	// Severity classifies the risk of the finding.
	Severity Severity
	// Address is the address of the offending resource.
	Address string
	// Message describes the detected risk.
	Message string
}

// Rule inspects a single resource and returns the findings it produces.
// A rule returns no findings for resource types it does not understand.
type Rule interface {
	ID() string
	Check(Resource) []Finding
}

// DefaultRules returns the security baseline rules applied by Evaluate.
func DefaultRules() []Rule {
	return []Rule{
		S3BucketPublicACLRule{},
		S3BucketPublicPolicyRule{},
		S3BucketPublicAccessBlockRule{},
		SecurityGroupOpenIngressRule{},
	}
}

// Evaluate runs the given rules against every resource and returns all
// findings in resource order. A nil rule set uses DefaultRules.
func Evaluate(resources []Resource, rules []Rule) []Finding {
	if rules == nil {
		rules = DefaultRules()
	}

	var findings []Finding

	for _, resource := range resources {
		for _, rule := range rules {
			findings = append(findings, rule.Check(resource)...)
		}
	}

	return findings
}
