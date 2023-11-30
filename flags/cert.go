package flags

import (
	"strings"
)

type CertFlag []byte

func (flag *CertFlag) Set(val string) error {
	result, err := flagFormatParser(val, flagFormatB64|flagFormatEnvB64|flagFormatFile)

	if err != nil {
		return err
	}

	if result == "" {
		resultBytes, err := readFromFile(val, true)

		if err != nil {
			return err
		}

		result = string(resultBytes)
	}

	*flag = CertFlag(result)
	return nil
}

func (flag *CertFlag) Type() string {
	return "env-b64:<cert>,b64:<cert>,<cert-file-name>"
}

func (flag *CertFlag) String() string {
	return string(*flag)
}

type CertPathFlag [][]byte

func (slice *CertPathFlag) Set(val string) error {
	resultBytes, err := readFromPath(val, true)

	if err != nil {
		return err
	}

	*slice = resultBytes
	return nil
}

func (slice *CertPathFlag) Type() string {
	return "<cert-path-name>"
}

func (slice *CertPathFlag) String() string {
	if len(*slice) == 0 {
		return ""
	}
	strList := []string{}

	for _, certBytes := range *slice {
		strList = append(strList, string(certBytes))
	}

	return "[" + strings.Join(strList, ", ") + "]"
}
