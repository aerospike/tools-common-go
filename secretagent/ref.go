package secretagent

import (
	"fmt"
	"strings"
)

const secretPrefix = "secrets:"

// Ref is a parsed secrets:[<resource>:]<key> reference. Resource is empty when
// the reference names only a key.
type Ref struct {
	Resource string
	Key      string
}

// IsSecret reports whether value is a secret reference rather than a literal.
func IsSecret(value string) bool {
	return strings.HasPrefix(value, secretPrefix)
}

// ParseRef parses secrets:[<resource>:]<key>. Like the Aerospike C tools, it
// splits on the last colon, so the resource may itself contain colons.
func ParseRef(value string) (Ref, error) {
	path, ok := strings.CutPrefix(value, secretPrefix)
	if !ok {
		return Ref{}, fmt.Errorf("%w: not a secret reference, expected %s[<resource>:]<key>",
			ErrInvalidConfig, secretPrefix)
	}

	var ref Ref

	ref.Key = path

	if i := strings.LastIndexByte(path, ':'); i >= 0 {
		ref.Resource, ref.Key = path[:i], path[i+1:]
	}

	if ref.Key == "" {
		return Ref{}, fmt.Errorf("%w: secret reference %q has an empty key", ErrInvalidConfig, value)
	}

	return ref, nil
}

// String returns the reference in secrets:[<resource>:]<key> form.
func (r Ref) String() string {
	if r.Resource == "" {
		return secretPrefix + r.Key
	}

	return secretPrefix + r.Resource + ":" + r.Key
}
