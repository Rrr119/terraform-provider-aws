// Copyright IBM Corp. 2026
// SPDX-License-Identifier: MPL-2.0

package securitybaseline

import (
	"fmt"

	tfjson "github.com/hashicorp/terraform-json"
)

// planActionsChecked are the change actions whose planned values must satisfy
// the baseline. Read ("no-op") resources are already covered when they were
// created, and deleted resources introduce no new exposure.
var planActionsChecked = map[tfjson.Action]bool{
	tfjson.ActionCreate: true,
	tfjson.ActionUpdate: true,
}

// LoadPlan parses a Terraform JSON plan (the output of
// `terraform show -json plan.tfplan`) and returns the resources whose planned
// values must satisfy the security baseline.
func LoadPlan(data []byte) ([]Resource, error) {
	plan := tfjson.Plan{}
	if err := plan.UnmarshalJSON(data); err != nil {
		return nil, fmt.Errorf("parsing terraform plan: %w", err)
	}

	resources := make([]Resource, 0, len(plan.ResourceChanges))

	for _, change := range plan.ResourceChanges {
		if change == nil || change.Change == nil || !managedResource(change) {
			continue
		}

		if !actionChecked(change.Change.Actions) {
			continue
		}

		values, ok := change.Change.After.(map[string]any)
		if !ok {
			continue
		}

		resources = append(resources, Resource{
			Address: change.Address,
			Type:    change.Type,
			Values:  normalizePlanValues(values),
		})
	}

	return resources, nil
}

func managedResource(change *tfjson.ResourceChange) bool {
	return change.Mode == tfjson.ManagedResourceMode
}

func actionChecked(actions tfjson.Actions) bool {
	for _, action := range actions {
		if planActionsChecked[action] {
			return true
		}
	}

	return false
}

// normalizePlanValues keeps the plan representation aligned with the HCL
// representation. The JSON decoder produces float64 for numbers, so integer
// attributes are converted back to int for the rule helpers.
func normalizePlanValues(values map[string]any) map[string]any {
	normalized := make(map[string]any, len(values))

	for key, value := range values {
		normalized[key] = normalizePlanValue(value)
	}

	return normalized
}

func normalizePlanValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		return normalizePlanValues(typed)
	case []any:
		result := make([]any, len(typed))

		for index, item := range typed {
			result[index] = normalizePlanValue(item)
		}

		return result
	case float64:
		return int(typed)
	default:
		return value
	}
}
