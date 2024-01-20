package flags

import (
	"reflect"

	"github.com/mitchellh/mapstructure"
)

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
	return "\"env-b64:<env-var>,b64:<b64-pass>,file:<pass-file>,<clear-pass>\""
}

func (flag *PasswordFlag) String() string {
	return string(*flag)
}

func PasswordFlagHookFunc() mapstructure.DecodeHookFuncType {
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
		if t != reflect.TypeOf(PasswordFlag{}) {
			return data, nil
		}

		// Return the parsed value
		flag := PasswordFlag{}

		if err := flag.Set(data.(string)); err != nil {
			return data, err
		}

		return flag, nil
	}
}
