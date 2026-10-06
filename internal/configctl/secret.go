package configctl

import (
	"crypto/rand"
	"fmt"
	"io"
	"reflect"
	"strings"

	"gopkg.in/yaml.v3"
)

// sensitiveConfigPaths are never returned in diffs and may only be edited
// through ${SECRET:KEEP}/${SECRET:CLEAR} placeholders.
var sensitiveConfigPaths = map[string]struct{}{
	"pow.public_salt":            {},
	"pow.allowed_previous_salts": {},
	"storage.postgres.dsn":       {},
	"storage.redis.password":     {},
	"logging.log_salt":           {},
}

func isSensitivePath(path string) bool {
	_, ok := sensitiveConfigPaths[strings.ToLower(path)]
	return ok
}

// RedactYAML returns the configuration with every sensitive value replaced
// by ${SECRET:KEEP}.
func RedactYAML(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	var node map[string]interface{}
	if yaml.Unmarshal(raw, &node) != nil {
		return "# redacted configuration unavailable"
	}
	redactMap("", node)
	out, err := yaml.Marshal(node)
	if err != nil {
		return "# redacted configuration unavailable"
	}
	return string(out)
}

func redactMap(prefix string, node map[string]interface{}) {
	for key, value := range node {
		path := key
		if prefix != "" {
			path = prefix + "." + key
		}
		if isSensitivePath(path) {
			node[key] = "${SECRET:KEEP}"
			continue
		}
		if child, ok := value.(map[string]interface{}); ok {
			redactMap(path, child)
		}
		if list, ok := value.([]interface{}); ok {
			for _, item := range list {
				if child, ok := item.(map[string]interface{}); ok {
					redactMap(path, child)
				}
			}
		}
	}
}

// mergeSecretPlaceholders folds an edited document back into a full
// candidate: ${SECRET:KEEP} pulls the live value from base, ${SECRET:CLEAR}
// empties it, literal edits of sensitive fields are rejected.
func mergeSecretPlaceholders(raw string, current []byte) ([]byte, error) {
	if len(current) == 0 {
		return nil, fmt.Errorf("secret merge: no base configuration")
	}
	var candidate, base map[string]interface{}
	if err := yaml.Unmarshal([]byte(raw), &candidate); err != nil {
		return nil, fmt.Errorf("invalid YAML candidate")
	}
	if err := yaml.Unmarshal(current, &base); err != nil {
		return nil, fmt.Errorf("secret merge: base configuration is not valid YAML")
	}
	if err := mergeSecretMap("", candidate, base); err != nil {
		return nil, err
	}
	out, err := yaml.Marshal(candidate)
	if err != nil {
		return nil, fmt.Errorf("secret merge: marshal")
	}
	return out, nil
}

func mergeSecretMap(prefix string, candidate, base map[string]interface{}) error {
	for key, baseValue := range base {
		path := key
		if prefix != "" {
			path = prefix + "." + key
		}
		candidateValue, exists := candidate[key]
		if isSensitivePath(path) && !exists {
			return fmt.Errorf("secret merge: %s was removed; sensitive fields must keep their placeholder", path)
		}
		if baseChild, ok := baseValue.(map[string]interface{}); ok {
			candidateChild, _ := candidateValue.(map[string]interface{})
			if candidateChild == nil {
				candidateChild = map[string]interface{}{}
			}
			if err := mergeSecretMap(path, candidateChild, baseChild); err != nil {
				return err
			}
		}
	}
	for key, value := range candidate {
		path := key
		if prefix != "" {
			path = prefix + "." + key
		}
		if isSensitivePath(path) {
			text, isText := value.(string)
			switch {
			case isText && text == "${SECRET:KEEP}":
				baseValue, ok := base[key]
				if !ok {
					return fmt.Errorf("secret merge: %s has no base value", path)
				}
				candidate[key] = baseValue
			case isText && text == "${SECRET:CLEAR}":
				candidate[key] = emptySecretValue(base[key])
			case reflect.DeepEqual(value, base[key]):
				// An unchanged literal is tolerated; it never came from a diff.
			default:
				return fmt.Errorf("secret merge: %s must use $%s or $%s placeholders", path, "{SECRET:KEEP}", "{SECRET:CLEAR}")
			}
			continue
		}
		if text, ok := value.(string); ok && strings.HasPrefix(text, "${SECRET:") {
			return fmt.Errorf("secret merge: %s carries a placeholder but is not sensitive", path)
		}
		if child, ok := value.(map[string]interface{}); ok {
			if _, exists := base[key].(map[string]interface{}); !exists {
				if err := rejectSecretPlaceholderMap(path, child); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func rejectSecretPlaceholderMap(prefix string, node map[string]interface{}) error {
	for key, value := range node {
		path := prefix + "." + key
		if isSensitivePath(path) {
			return fmt.Errorf("secret merge: %s was added; sensitive fields cannot be introduced this way", path)
		}
		if text, ok := value.(string); ok && strings.HasPrefix(text, "${SECRET:") {
			return fmt.Errorf("secret merge: %s carries a placeholder but is not sensitive", path)
		}
		if child, ok := value.(map[string]interface{}); ok {
			if err := rejectSecretPlaceholderMap(path, child); err != nil {
				return err
			}
		}
	}
	return nil
}

func emptySecretValue(value interface{}) interface{} {
	switch value.(type) {
	case []interface{}, []string:
		return []interface{}{}
	default:
		return ""
	}
}

// equalValue compares YAML values structurally.
func equalValue(before, after interface{}) bool { return reflect.DeepEqual(before, after) }

func readRandom(b []byte) (int, error) { return io.ReadFull(rand.Reader, b) }
