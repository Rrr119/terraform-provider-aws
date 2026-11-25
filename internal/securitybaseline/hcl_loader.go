// Copyright IBM Corp. 2026
// SPDX-License-Identifier: MPL-2.0

package securitybaseline

import (
	"fmt"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
)

// LoadConfig parses Terraform HCL configuration bytes and returns the
// declared resources. Only literal attribute values are decoded; references
// and other dynamic expressions are retained as their source text so the
// loader never fails on a valid but variable-driven configuration.
func LoadConfig(filename string, src []byte) ([]Resource, hcl.Diagnostics) {
	file, diags := hclsyntax.ParseConfig(src, filename, hcl.Pos{Line: 1, Column: 1})
	if diags.HasErrors() {
		return nil, diags
	}

	content, _, contentDiags := file.Body.PartialContent(&hcl.BodySchema{
		Blocks: []hcl.BlockHeaderSchema{
			{Type: "resource", LabelNames: []string{"type", "name"}},
		},
	})
	diags = append(diags, contentDiags...)

	if content == nil {
		return nil, diags
	}

	resources := make([]Resource, 0, len(content.Blocks))

	for _, block := range content.Blocks {
		if block.Type != "resource" || len(block.Labels) < 2 {
			continue
		}

		values := decodeBody(block.Body, src)

		resources = append(resources, Resource{
			Address: fmt.Sprintf("%s.%s", block.Labels[0], block.Labels[1]),
			Type:    block.Labels[0],
			Values:  values,
		})
	}

	return resources, diags
}

// decodeBody decodes the attributes and nested blocks of a resource or block.
// The native syntax exposes both directly on the syntax tree, which avoids
// requiring a schema for every possible nested block type.
func decodeBody(body hcl.Body, src []byte) map[string]any {
	syntaxBody, ok := body.(*hclsyntax.Body)
	if !ok {
		return map[string]any{}
	}

	values := make(map[string]any, len(syntaxBody.Attributes))

	for name, attribute := range syntaxBody.Attributes {
		values[name] = decodeExpression(attribute.Expr, src)
	}

	blocksByType := map[string][]any{}

	for _, child := range syntaxBody.Blocks {
		blocksByType[child.Type] = append(blocksByType[child.Type], decodeBody(child.Body, src))
	}

	for blockType, blocks := range blocksByType {
		values[blockType] = blocks
	}

	return values
}

func decodeExpression(expression hcl.Expression, src []byte) any {
	// Literal values decode without an evaluation context.
	literal, diags := expression.Value(nil)
	if !diags.HasErrors() {
		return ctyValue(literal)
	}

	// Fall back to the source text for references and other dynamic values.
	return string(expression.Range().SliceBytes(src))
}
