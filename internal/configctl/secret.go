package configctl

import (
	"bytes"
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
//
// Redaction works on the parsed node tree rather than a decoded map, so key
// order, comments and the file's own indentation all survive. That matters
// because this exact text is what `config show` prints and `config edit`
// opens in $EDITOR: a rebuild through a map would reorder the keys, drop
// every comment and re-indent the file the first time it is edited.
func RedactYAML(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	raw = normalizeCRLF(raw)
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return "# redacted configuration unavailable"
	}
	redactNode("", &doc)
	out, err := encodeYAML(&doc, detectIndent(raw))
	if err != nil {
		return "# redacted configuration unavailable"
	}
	return out
}

// redactNode walks the node tree replacing sensitive scalars with the KEEP
// placeholder. prefix is the dotted path from the document root.
func redactNode(prefix string, node *yaml.Node) {
	switch node.Kind {
	case yaml.DocumentNode:
		for _, child := range node.Content {
			redactNode(prefix, child)
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(node.Content); i += 2 {
			key := node.Content[i]
			val := node.Content[i+1]
			path := joinPath(prefix, key.Value)
			if isSensitivePath(path) {
				setPlaceholder(val, "${SECRET:KEEP}")
				continue
			}
			redactNode(path, val)
		}
	case yaml.SequenceNode:
		for _, item := range node.Content {
			redactNode(prefix, item)
		}
	}
}

// mergeSecretPlaceholders folds an edited document back into a full
// candidate: ${SECRET:KEEP} pulls the live value from base, ${SECRET:CLEAR}
// empties it, literal edits of sensitive fields are rejected. The output
// keeps the edited text's comments, ordering and indentation.
func mergeSecretPlaceholders(raw string, current []byte) ([]byte, error) {
	if len(current) == 0 {
		return nil, fmt.Errorf("secret merge: no base configuration")
	}
	rawBytes := normalizeCRLF([]byte(raw))
	var candidate, base yaml.Node
	if err := yaml.Unmarshal(rawBytes, &candidate); err != nil {
		return nil, fmt.Errorf("invalid YAML candidate")
	}
	if err := yaml.Unmarshal(normalizeCRLF(current), &base); err != nil {
		return nil, fmt.Errorf("secret merge: base configuration is not valid YAML")
	}
	if err := mergeSecretNode("", &candidate, &base); err != nil {
		return nil, err
	}
	out, err := encodeYAML(&candidate, detectIndent(rawBytes))
	if err != nil {
		return nil, fmt.Errorf("secret merge: marshal")
	}
	return []byte(out), nil
}

// normalizeCRLF strips carriage returns before parsing. Without it yaml.v3
// keeps a \r on every comment line, and re-encoding then separates each
// comment line with a blank line.
func normalizeCRLF(raw []byte) []byte {
	if !bytes.Contains(raw, []byte("\r")) {
		return raw
	}
	return bytes.ReplaceAll(raw, []byte("\r\n"), []byte("\n"))
}

func mergeSecretNode(prefix string, cand, base *yaml.Node) error {
	cand = docRoot(cand)
	base = docRoot(base)
	if base.Kind != yaml.MappingNode {
		return nil
	}
	baseMap := mappingEntries(base)
	candMap := map[string]*yaml.Node{}
	if cand.Kind == yaml.MappingNode {
		candMap = mappingEntries(cand)
	}

	// Sensitive base fields must survive, and shared mapping children are
	// recursed into so nested placeholders are resolved in the sub-call.
	for i := 0; i+1 < len(base.Content); i += 2 {
		key := base.Content[i].Value
		baseVal := base.Content[i+1]
		path := joinPath(prefix, key)
		if isSensitivePath(path) {
			if _, ok := candMap[key]; !ok {
				return fmt.Errorf("secret merge: %s was removed; sensitive fields must keep their placeholder", path)
			}
			continue
		}
		if docRoot(baseVal).Kind == yaml.MappingNode {
			if candVal, ok := candMap[key]; ok {
				if err := mergeSecretNode(path, candVal, baseVal); err != nil {
					return err
				}
			}
		}
	}

	if cand.Kind != yaml.MappingNode {
		return nil
	}
	// Candidate side: resolve placeholders and reject illegal edits.
	for i := 0; i+1 < len(cand.Content); i += 2 {
		key := cand.Content[i].Value
		val := cand.Content[i+1]
		path := joinPath(prefix, key)
		if isSensitivePath(path) {
			baseVal, ok := baseMap[key]
			if !ok {
				return fmt.Errorf("secret merge: %s has no base value", path)
			}
			text, isText := scalarText(val)
			switch {
			case isText && text == "${SECRET:KEEP}":
				replaceNode(val, baseVal)
			case isText && text == "${SECRET:CLEAR}":
				replaceNode(val, emptyNode(baseVal))
			case equalValue(decodeNode(val), decodeNode(baseVal)):
				// An unchanged literal is tolerated; it never came from a diff.
			default:
				return fmt.Errorf("secret merge: %s must use $%s or $%s placeholders", path, "{SECRET:KEEP}", "{SECRET:CLEAR}")
			}
			continue
		}
		if text, ok := scalarText(val); ok && strings.HasPrefix(text, "${SECRET:") {
			return fmt.Errorf("secret merge: %s carries a placeholder but is not sensitive", path)
		}
		if _, exists := baseMap[key]; !exists && docRoot(val).Kind == yaml.MappingNode {
			if err := rejectSecretPlaceholderMap(path, val); err != nil {
				return err
			}
		}
	}
	return nil
}

func rejectSecretPlaceholderMap(prefix string, node *yaml.Node) error {
	node = docRoot(node)
	if node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		key := node.Content[i].Value
		val := node.Content[i+1]
		path := joinPath(prefix, key)
		if isSensitivePath(path) {
			return fmt.Errorf("secret merge: %s was added; sensitive fields cannot be introduced this way", path)
		}
		if text, ok := scalarText(val); ok && strings.HasPrefix(text, "${SECRET:") {
			return fmt.Errorf("secret merge: %s carries a placeholder but is not sensitive", path)
		}
		if err := rejectSecretPlaceholderMap(path, val); err != nil {
			return err
		}
	}
	return nil
}

// equalValue compares YAML values structurally.
func equalValue(before, after interface{}) bool { return reflect.DeepEqual(before, after) }

func decodeNode(n *yaml.Node) interface{} {
	if n == nil {
		return nil
	}
	var v interface{}
	if err := n.Decode(&v); err != nil {
		return nil
	}
	return v
}

// setPlaceholder rewrites a scalar in place. Comments attached to the node
// are deliberately left untouched.
func setPlaceholder(n *yaml.Node, text string) {
	n.Kind = yaml.ScalarNode
	n.Tag = "!!str"
	n.Value = text
	n.Style = 0
	n.Content = nil
	n.Alias = nil
}

// replaceNode overwrites dst with a deep copy of src so the base and
// candidate documents never share nodes.
func replaceNode(dst, src *yaml.Node) {
	*dst = *deepCopyNode(src)
}

func deepCopyNode(n *yaml.Node) *yaml.Node {
	if n == nil {
		return nil
	}
	c := *n
	c.Content = make([]*yaml.Node, len(n.Content))
	for i, child := range n.Content {
		c.Content[i] = deepCopyNode(child)
	}
	c.Alias = nil
	return &c
}

// emptyNode returns the cleared form of a sensitive value: an empty list
// stays a list, anything else becomes an explicitly empty string.
func emptyNode(baseVal *yaml.Node) *yaml.Node {
	if docRoot(baseVal).Kind == yaml.SequenceNode {
		return &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	}
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Style: yaml.DoubleQuotedStyle}
}

func docRoot(n *yaml.Node) *yaml.Node {
	if n != nil && n.Kind == yaml.DocumentNode && len(n.Content) == 1 {
		return n.Content[0]
	}
	return n
}

func mappingEntries(n *yaml.Node) map[string]*yaml.Node {
	out := map[string]*yaml.Node{}
	if n == nil || n.Kind != yaml.MappingNode {
		return out
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		out[n.Content[i].Value] = n.Content[i+1]
	}
	return out
}

func scalarText(n *yaml.Node) (string, bool) {
	n = docRoot(n)
	if n != nil && n.Kind == yaml.ScalarNode && (n.Tag == "!!str" || n.Tag == "") {
		return n.Value, true
	}
	return "", false
}

func joinPath(prefix, key string) string {
	if prefix == "" {
		return key
	}
	return prefix + "." + key
}

// encodeYAML serialises the node tree with the given indent width. The
// Encoder (rather than yaml.Marshal) is required because only it can keep
// the original indentation.
func encodeYAML(doc *yaml.Node, indent int) (string, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(indent)
	if err := enc.Encode(doc); err != nil {
		_ = enc.Close()
		return "", err
	}
	if err := enc.Close(); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// detectIndent reports the smallest positive indentation in the source, so a
// round-trip keeps the file's own width instead of re-indenting it.
func detectIndent(raw []byte) int {
	width := 0
	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimLeft(line, " ")
		if trimmed == "" || len(trimmed) == len(line) {
			continue
		}
		n := len(line) - len(trimmed)
		if width == 0 || n < width {
			width = n
		}
	}
	if width < 1 || width > 8 {
		return 2
	}
	return width
}

func readRandom(b []byte) (int, error) { return io.ReadFull(rand.Reader, b) }
