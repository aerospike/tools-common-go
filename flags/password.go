package flags

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
)

const (
	passwordMaxLen           = 63
	tlsKeyFilePasswordMaxLen = 1024
)

const (
	envPrefix    = "env:"
	envB64Prefix = "env-b64:"
	b64Prefix    = "b64:"
	filePrefix   = "file:"
)

const asciiSpace = " \t\n\v\f\r"

// PasswordFlag defines a Cobra compatible
// flag for password related options.
// examples include
// --password
// --tls-keyfile-password
type PasswordFlag []byte

func (flag *PasswordFlag) Set(val string) error {
	result, err := flagFormatParser(val, flagFormatB64|flagFormatEnvB64|flagFormatFile|flagFormatEnv)
	if err != nil {
		return err
	}

	if err == nil && result == "" {
		result = val
	}

	*flag = PasswordFlag(result)

	return nil
}

func (flag *PasswordFlag) Type() string {
	return "\"env:<env-var>,env-b64:<env-var>,b64:<b64-pass>,file:<pass-file>,secrets:<resource>:<key>,<clear-pass>\""
}

func (flag *PasswordFlag) String() string {
	return string(*flag)
}

// hasPasswordSource reports whether value names where a password lives rather
// than being the password.
func hasPasswordSource(value string) bool {
	for _, prefix := range []string{envPrefix, envB64Prefix, b64Prefix, filePrefix} {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}

	return false
}

// readPassword returns the password value names: the value of env:<VAR>, the
// decoded env-b64:<VAR> or b64:<BASE64>, the contents of file:<PATH> less one
// trailing line ending (only the first line with firstLine), or value itself.
// The result must be at most maxLen bytes. Errors start with label and never
// contain the password.
func readPassword(label, value string, maxLen int, firstLine bool) (string, error) {
	var (
		password, what string
		err            error
	)

	switch {
	case strings.HasPrefix(value, envPrefix):
		name := strings.TrimPrefix(value, envPrefix)
		if name == "" {
			return "", fmt.Errorf("%s: env: requires a variable name", label)
		}

		password, err = passwordFromEnv(label, name)
		what = "value from environment variable " + name
	case strings.HasPrefix(value, envB64Prefix):
		name := strings.TrimPrefix(value, envB64Prefix)
		if name == "" {
			return "", fmt.Errorf("%s: env-b64: requires a variable name", label)
		}

		if password, err = passwordFromEnv(label, name); err == nil {
			password, err = decodePassword(label, password, "environment variable "+name)
		}

		what = "decoded value from environment variable " + name
	case strings.HasPrefix(value, b64Prefix):
		password, err = decodePassword(label, strings.TrimPrefix(value, b64Prefix), "b64: value")
		what = "decoded b64: value"
	case strings.HasPrefix(value, filePrefix):
		path := strings.TrimPrefix(value, filePrefix)
		if path == "" {
			return "", fmt.Errorf("%s: file: requires a path", label)
		}

		password, err = passwordFromFile(label, path, maxLen, firstLine)
		what = "value from file " + path
	default:
		password, what = value, "password"
	}

	if err != nil {
		return "", err
	}

	return password, checkPasswordLen(label, what, password, maxLen)
}

func checkPasswordLen(label, what, password string, maxLen int) error {
	if len(password) > maxLen {
		return fmt.Errorf("%s: %s is longer than %d bytes", label, what, maxLen)
	}

	return nil
}

func passwordFromEnv(label, name string) (string, error) {
	value := os.Getenv(name)
	if value == "" {
		return "", fmt.Errorf("%s: environment variable %s is not set or empty", label, name)
	}

	return value, nil
}

func decodePassword(label, encoded, source string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("%s: invalid base64 in %s", label, source)
	}

	if bytes.IndexByte(data, 0) >= 0 {
		return "", fmt.Errorf("%s: %s decodes to a value containing a NUL byte", label, source)
	}

	data = bytes.TrimSuffix(data, []byte("\n"))
	if len(data) == 0 {
		return "", fmt.Errorf("%s: password from %s is empty", label, source)
	}

	return string(data), nil
}

// passwordFromFile reads at most maxLen+3 bytes, room for a line ending and
// one byte more, so an over-long value is caught without reading the rest.
func passwordFromFile(label, path string, maxLen int, firstLine bool) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fileReadError(label, path, err)
	}

	defer file.Close()

	reader := bufio.NewReader(io.LimitReader(file, int64(maxLen)+3))
	lineEnded := false

	var data []byte

	for {
		c, err := reader.ReadByte()
		if errors.Is(err, io.EOF) {
			break
		}

		if err != nil {
			return "", fileReadError(label, path, err)
		}

		if c == 0 {
			return "", fmt.Errorf("%s: file %s contains a NUL byte", label, path)
		}

		if firstLine && (c == '\n' || c == '\r') {
			lineEnded = true
			break
		}

		data = append(data, c)
	}

	if trimmed, found := bytes.CutSuffix(data, []byte("\n")); found {
		data = bytes.TrimSuffix(trimmed, []byte("\r"))
	}

	if len(data) == 0 {
		if lineEnded {
			return "", fmt.Errorf("%s: password from first line of file %s is empty", label, path)
		}

		return "", fmt.Errorf("%s: password from file %s is empty", label, path)
	}

	return string(data), nil
}

func fileReadError(label, path string, err error) error {
	var pathErr *fs.PathError
	if errors.As(err, &pathErr) {
		err = pathErr.Err
	}

	return fmt.Errorf("%s: cannot read file %s: %w", label, path, err)
}
