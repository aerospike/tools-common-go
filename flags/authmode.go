package flags

import (
	"fmt"
	"reflect"
	"strings"

	as "github.com/aerospike/aerospike-client-go/v6"
	"github.com/mitchellh/mapstructure"
)

// AuthModeFlag defines a Cobra compatible flag for the
// --auth flag.
type AuthModeFlag as.AuthMode

var authModeMap = map[string]as.AuthMode{
	"INTERNAL": as.AuthModeInternal,
	"EXTERNAL": as.AuthModeExternal,
	"PKI":      as.AuthModePKI,
}

func (mode *AuthModeFlag) Set(val string) error {
	val = strings.ToUpper(val)
	if val, ok := authModeMap[val]; ok {
		*mode = AuthModeFlag(val)
		return nil
	}

	return fmt.Errorf("unrecognized auth mode")
}

func (mode *AuthModeFlag) Type() string {
	return "INTERNAL,EXTERNAL,PKI"
}

func (mode *AuthModeFlag) String() string {
	for k, v := range authModeMap {
		if AuthModeFlag(v) == *mode {
			return k
		}
	}

	return ""
}

func AuthModeFlagHookFunc() mapstructure.DecodeHookFuncType {
	return func(
		f reflect.Type,
		t reflect.Type,
		data interface{},
	) (interface{}, error) {
		// Check that the data is string
		if f.Kind() != reflect.String {
			return data, nil
		}

		// Check that the target type is our custom type
		if t != reflect.TypeOf(AuthModeFlag(0)) {
			return data, nil
		}

		// Return the parsed value
		flag := AuthModeFlag(as.AuthModeInternal)

		if err := flag.Set(data.(string)); err != nil {
			return data, err
		}

		return flag, nil
	}
}
