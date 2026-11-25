// Copyright IBM Corp. 2026
// SPDX-License-Identifier: MPL-2.0

package securitybaseline

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// Rule SG01 evaluates security group ingress rules.
const securityGroupIngressRuleID = "SG01"

// Risky ports per the AWS security baseline: administrative and data services
// that must never be reachable from the entire internet.
var riskyPorts = map[int]string{
	22:    "SSH",
	23:    "Telnet",
	3389:  "RDP",
	3306:  "MySQL",
	5432:  "PostgreSQL",
	6379:  "Redis",
	27017: "MongoDB",
	9200:  "Elasticsearch",
}

var worldOpenCIDRs = []string{"0.0.0.0/0", "::/0"}

// SecurityGroupOpenIngressRule flags ingress rules that open a risky port, or
// all protocols, to the entire internet. Egress rules are ignored because
// unrestricted outbound traffic is the AWS default and not an exposure.
type SecurityGroupOpenIngressRule struct{}

// ID returns the rule identifier.
func (SecurityGroupOpenIngressRule) ID() string {
	return securityGroupIngressRuleID
}

// Check inspects inline ingress blocks and standalone security group rules.
func (rule SecurityGroupOpenIngressRule) Check(resource Resource) []Finding {
	switch resource.Type {
	case "aws_security_group":
		return rule.checkInline(resource)
	case "aws_security_group_rule", "aws_vpc_security_group_ingress_rule":
		return rule.checkStandalone(resource)
	default:
		return nil
	}
}

func (rule SecurityGroupOpenIngressRule) checkInline(resource Resource) []Finding {
	var findings []Finding

	for _, ingress := range nestedBlocks(resource.Values, "ingress") {
		if message, risky := riskyIngressMessage(ingress); risky {
			findings = append(findings, Finding{
				RuleID:   rule.ID(),
				Severity: SeverityHigh,
				Address:  resource.Address,
				Message:  message,
			})
		}
	}

	return findings
}

func (rule SecurityGroupOpenIngressRule) checkStandalone(resource Resource) []Finding {
	if direction := stringValue(resource.Values, "type"); direction != "" && direction != "ingress" {
		return nil
	}

	message, risky := riskyIngressMessage(resource.Values)
	if !risky {
		return nil
	}

	return []Finding{{
		RuleID:   rule.ID(),
		Severity: SeverityHigh,
		Address:  resource.Address,
		Message:  message,
	}}
}

// riskyIngressMessage evaluates one normalized ingress rule map and returns a
// finding message when it reaches the world on a risky port or all protocols.
func riskyIngressMessage(rule map[string]any) (string, bool) {
	if !openToWorld(rule) {
		return "", false
	}

	protocol := strings.ToLower(firstString(rule, "protocol", "ip_protocol"))
	if protocol == "" {
		return "", false
	}

	if protocol == "-1" || protocol == "all" {
		return "security group ingress allows all protocols from the entire internet", true
	}

	fromPort, fromOK := intFromAny(firstValue(rule, "from_port", "from_port_range"))
	toPort, toOK := intFromAny(firstValue(rule, "to_port", "to_port_range"))

	if !fromOK || !toOK || fromPort < 0 || toPort < 0 {
		return "", false
	}

	for port := range riskyPorts {
		if port >= fromPort && port <= toPort {
			return fmt.Sprintf("security group ingress opens %s (port %d) to the entire internet", riskyPorts[port], port), true
		}
	}

	return "", false
}

func firstString(values map[string]any, keys ...string) string {
	for _, key := range keys {
		if value := stringValue(values, key); value != "" {
			return value
		}
	}

	return ""
}

func firstValue(values map[string]any, keys ...string) any {
	for _, key := range keys {
		if value, ok := values[key]; ok {
			return value
		}
	}

	return nil
}

// openToWorld reports whether the rule sources traffic from an unrestricted
// CIDR. The standalone VPC ingress rule resource uses cidr_ipv4/cidr_ipv6
// while the classic resources use cidr_blocks/ipv6_cidr_blocks.
func openToWorld(rule map[string]any) bool {
	for _, key := range []string{"cidr_ipv4", "cidr_ipv6"} {
		cidr := stringValue(rule, key)
		if cidr != "" && containsWorldPrefix(cidr) {
			return true
		}
	}

	for _, key := range []string{"cidr_blocks", "ipv6_cidr_blocks"} {
		for _, cidr := range stringList(rule[key]) {
			if containsWorldPrefix(cidr) {
				return true
			}
		}
	}

	return false
}

// containsWorldPrefix treats both exact world CIDRs and any prefix that
// contains the entire address family as open to the internet.
func containsWorldPrefix(cidr string) bool {
	if slices.Contains(worldOpenCIDRs, cidr) {
		return true
	}

	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return false
	}

	return prefix.Bits() == 0
}

func stringList(value any) []string {
	items, ok := value.([]any)
	if !ok {
		return nil
	}

	result := make([]string, 0, len(items))

	for _, item := range items {
		if text, ok := item.(string); ok {
			result = append(result, text)
		}
	}

	return result
}
