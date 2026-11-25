// Copyright IBM Corp. 2026
// SPDX-License-Identifier: MPL-2.0

package securitybaseline_test

import (
	"fmt"

	"github.com/hashicorp/terraform-provider-aws/internal/securitybaseline"
)

func ExampleLoadConfig() {
	src := []byte(`
resource "aws_security_group" "example" {
  name = "example"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
`)

	resources, diags := securitybaseline.LoadConfig("main.tf", src)
	if diags.HasErrors() {
		fmt.Println(diags.Error())
		return
	}

	for _, finding := range securitybaseline.Evaluate(resources, nil) {
		fmt.Printf("%s %s: %s\n", finding.RuleID, finding.Address, finding.Message)
	}

	// Output:
	// SG01 aws_security_group.example: security group ingress opens SSH (port 22) to the entire internet
}

func ExampleLoadPlan() {
	// Produced by `terraform show -json plan.tfplan` during the existing plan
	// workflow; only the resource_changes section is shown here.
	plan := []byte(`{
	  "format_version": "1.2",
	  "resource_changes": [
	    {
	      "address": "aws_s3_bucket.example",
	      "mode": "managed",
	      "type": "aws_s3_bucket",
	      "name": "example",
	      "change": {
	        "actions": ["create"],
	        "after": {"acl": "public-read"}
	      }
	    }
	  ]
}`)

	resources, err := securitybaseline.LoadPlan(plan)
	if err != nil {
		fmt.Println(err)
		return
	}

	for _, finding := range securitybaseline.Evaluate(resources, nil) {
		fmt.Println(finding.RuleID)
	}

	// Unordered output:
	// S301
	// S303
}
