// Copyright IBM Corp. 2026
// SPDX-License-Identifier: MPL-2.0

package securitybaseline

import "github.com/zclconf/go-cty/cty"

// ctyValue converts a decoded HCL value into the generic representation used by
// the rules: map[string]any, []any, and scalar Go types.
func ctyValue(value cty.Value) any {
	if value.IsNull() {
		return nil
	}

	ty := value.Type()

	switch {
	case ty == cty.String:
		return value.AsString()
	case ty == cty.Bool:
		return value.True()
	case ty == cty.Number:
		number, _ := value.AsBigFloat().Int64()
		return int(number)
	case ty.IsMapType() || ty.IsObjectType():
		result := map[string]any{}

		for key, item := range value.AsValueMap() {
			result[key] = ctyValue(item)
		}

		return result
	case ty.IsListType() || ty.IsSetType() || ty.IsTupleType():
		items := value.AsValueSlice()
		result := make([]any, len(items))

		for index, item := range items {
			result[index] = ctyValue(item)
		}

		return result
	default:
		return value.GoString()
	}
}
