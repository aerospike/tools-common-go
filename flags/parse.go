package flags

import (
	"fmt"
	"io"
	"os"
	"strings"
)

type flagFormat uint8

const (
	flagFormatEnv    = flagFormat(1)
	flagFormatEnvB64 = flagFormat(1 << 1)
	flagFormatB64    = flagFormat(1 << 2)
	flagFormatFile   = flagFormat(1 << 3)
)

var (
	ErrEnvironmentVariableNotFound = fmt.Errorf("environment variable not found")
)

func fromEnv(v string) (string, error) {
	result := os.Getenv(v)
	if result == "" {
		return "", ErrEnvironmentVariableNotFound
	}

	return result, nil
}

func fromBase64(v string) (string, error) {
	return decode64(v)
}

func fromFile(v string) (string, error) {
	resultBytes, err := readFromFile(v, true)
	// TODO is the special EOF handling needed?
	if err != nil && err != io.EOF {
		return "", err
	}

	return string(resultBytes), nil
}

func flagFormatParser(val string, mode flagFormat) (string, error) {
	split := strings.SplitN(val, ":", 2)
	sourceType := split[0]

	if len(split) < 2 {
		return "", nil
	}

	name := split[1]
	if (mode&flagFormatEnv) != 0 && sourceType == "env" {
		return fromEnv(name)
	} else if (mode&flagFormatEnvB64) != 0 && sourceType == "env-b64" {
		b64Val, err := fromEnv(name)
		if err != nil {
			return "", err
		}

		return fromBase64(b64Val)
	} else if (mode&flagFormatB64) != 0 && sourceType == "b64" {
		return fromBase64(name)
	} else if (mode&flagFormatFile) != 0 && sourceType == "file" {
		return fromFile(name)
	} else {
		return "", nil
	}
}
