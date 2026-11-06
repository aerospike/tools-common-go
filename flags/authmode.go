package flags

import (
	"fmt"
	"strings"

	as "github.com/aerospike/aerospike-client-go/v8"
)

// AuthModeFlag defines a Cobra compatible flag for the
// --auth flag.
type AuthModeFlag as.AuthMode

// AuthModeExternalInsecure is EXTERNAL authentication without TLS, which sends
// the password in clear, as EXTERNAL_INSECURE in the C tools.
const AuthModeExternalInsecure = AuthModeFlag(-1)

var authModeMap = map[string]AuthModeFlag{
	"INTERNAL":          AuthModeFlag(as.AuthModeInternal),
	"EXTERNAL":          AuthModeFlag(as.AuthModeExternal),
	"EXTERNAL_INSECURE": AuthModeExternalInsecure,
	"PKI":               AuthModeFlag(as.AuthModePKI),
}

func (mode *AuthModeFlag) Set(val string) error {
	val = strings.ToUpper(val)
	if val, ok := authModeMap[val]; ok {
		*mode = val
		return nil
	}

	return fmt.Errorf("unrecognized auth mode")
}

func (mode *AuthModeFlag) Type() string {
	return "INTERNAL,EXTERNAL,EXTERNAL_INSECURE,PKI"
}

func (mode *AuthModeFlag) String() string {
	for k, v := range authModeMap {
		if v == *mode {
			return k
		}
	}

	return ""
}
