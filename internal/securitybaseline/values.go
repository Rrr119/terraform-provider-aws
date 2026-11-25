// Copyright IBM Corp. 2026
// SPDX-License-Identifier: MPL-2.0

package securitybaseline

import (
	"encoding/json"
	"strconv"
	"strings"
)

// stringValue returns the string stored at key, or the empty string when the
// attribute is absent or not a string.
func stringValue(values map[string]any, key string) string {
	value, ok := values[key].(string)
	if !ok {
		return ""
	}

	return value
}

// boolValue returns the bool stored at key. The second result reports whether
// the attribute is present and a bool; an explicit false is therefore
// distinguishable from an unset attribute.
func boolValue(values map[string]any, key string) (bool, bool) {
	value, ok := values[key].(bool)
	return value, ok
}

// nestedBlocks returns the nested block maps stored under the block type name.
// Both decoded HCL blocks and JSON plan blocks use this shape.
func nestedBlocks(values map[string]any, blockType string) []map[string]any {
	raw, ok := values[blockType].([]any)
	if !ok {
		return nil
	}

	blocks := make([]map[string]any, 0, len(raw))

	for _, item := range raw {
		if block, ok := item.(map[string]any); ok {
			blocks = append(blocks, block)
		}
	}

	return blocks
}

// jsonStatement expands a policy document into its statement maps. The document
// may be a JSON string or an already-decoded map.
func jsonStatements(policy any) []map[string]any {
	var document map[string]any

	switch typed := policy.(type) {
	case string:
		if err := json.Unmarshal([]byte(typed), &document); err != nil {
			return nil
		}
	case map[string]any:
		document = typed
	default:
		return nil
	}

	switch statements := document["Statement"].(type) {
	case map[string]any:
		return []map[string]any{statements}
	case []any:
		result := make([]map[string]any, 0, len(statements))

		for _, statement := range statements {
			if mapped, ok := statement.(map[string]any); ok {
				result = append(result, mapped)
			}
		}

		return result
	default:
		return nil
	}
}

// allowsAnyPrincipal reports whether a policy statement grants access to any
// principal, including wildcard account identifiers.
func allowsAnyPrincipal(statement map[string]any) bool {
	principal, ok := statement["Principal"]
	if !ok {
		return false
	}

	switch typed := principal.(type) {
	case string:
		return typed == "*"
	case map[string]any:
		aws, ok := typed["AWS"]
		if !ok {
			return false
		}

		switch principals := aws.(type) {
		case string:
			return isWildcardPrincipal(principals)
		case []any:
			for _, candidate := range principals {
				if identifier, ok := candidate.(string); ok && isWildcardPrincipal(identifier) {
					return true
				}
			}
		}
	}

	return false
}

func isWildcardPrincipal(identifier string) bool {
	return identifier == "*"
}

// statementAllows reports whether a policy statement's effect permits access.
// A missing effect defaults to Allow, matching the IAM policy grammar.
func statementAllows(statement map[string]any) bool {
	effect, _ := statement["Effect"].(string)
	return strings.EqualFold(effect, "Allow") || effect == ""
}

// intFromAny decodes an integer attribute regardless of whether the loader
// produced an int (HCL) or a float64/json.Number (plan JSON).
func intFromAny(value any) (int, bool) {
	switch typed := value.(type) {
	case int:
		return typed, true
	case int64:
		return int(typed), true
	case float64:
		return int(typed), true
	case json.Number:
		parsed, err := typed.Int64()
		if err != nil {
			return 0, false
		}

		return int(parsed), true
	case string:
		parsed, err := strconv.Atoi(typed)
		if err != nil {
			return 0, false
		}

		return parsed, true
	default:
		return 0, false
	}
}
