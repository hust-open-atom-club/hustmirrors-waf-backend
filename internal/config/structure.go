package config

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// ValidateYAMLStructure rejects ambiguous YAML before Viper decoding. It keeps
// the managed configuration flow deterministic without returning source lines
// or values to Admin API callers.
func ValidateYAMLStructure(raw []byte) error {
	var root yaml.Node
	if err := yaml.Unmarshal(raw, &root); err != nil {
		return fmt.Errorf("config: invalid YAML structure")
	}
	seen := make(map[*yaml.Node]bool)
	if err := validateYAMLNode(&root, seen); err != nil {
		return err
	}
	return nil
}

func validateYAMLNode(node *yaml.Node, stack map[*yaml.Node]bool) error {
	if node == nil {
		return nil
	}
	if stack[node] {
		return fmt.Errorf("config: YAML alias cycle is not supported")
	}
	stack[node] = true
	defer delete(stack, node)

	if node.Kind == yaml.AliasNode {
		return validateYAMLNode(node.Alias, stack)
	}
	if node.Kind == yaml.MappingNode {
		keys := make(map[string]struct{}, len(node.Content)/2)
		for i := 0; i+1 < len(node.Content); i += 2 {
			key := node.Content[i]
			if key.Kind != yaml.ScalarNode || (key.Tag != "" && key.Tag != "!!str") {
				return fmt.Errorf("config: YAML mapping keys must be strings")
			}
			if _, ok := keys[key.Value]; ok {
				return fmt.Errorf("config: duplicate YAML key")
			}
			keys[key.Value] = struct{}{}
			if err := validateYAMLNode(node.Content[i+1], stack); err != nil {
				return err
			}
		}
		return nil
	}
	for _, child := range node.Content {
		if err := validateYAMLNode(child, stack); err != nil {
			return err
		}
	}
	return nil
}
