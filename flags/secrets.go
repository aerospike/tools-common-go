package flags

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	as "github.com/aerospike/aerospike-client-go/v8"
	"github.com/aerospike/tools-common-go/secretagent"
	"github.com/spf13/pflag"
)

var errSecretsNotTracked = errors.New("secret references are not tracked, use NewFlagSetWithSecrets")

// ResolveSecrets replaces secrets:[<resource>:]<key> values of --user,
// --password, --tls-cafile, --tls-certfile, --tls-keyfile and
// --tls-keyfile-password with values from the Secret Agent, and reads the
// env:, env-b64:, b64: and file: sources of --password and
// --tls-keyfile-password. The flags must come from NewFlagSetWithSecrets. Only
// values whose command line or config file text starts with secrets: are
// fetched, so a b64:, env:, env-b64: or file: value that expands to secrets:...
// stays literal, and fetched values are never parsed again. Call it after the
// flags and the config file are parsed, so option order does not matter, and
// before NewAerospikeConfig.
//
// The --tls-keyfile-password text has surrounding whitespace trimmed before
// its form, secrets: included, is read. --password is used as given.
//
// --password is read only with a user and an auth mode other than PKI, and
// --tls-keyfile-password only with a key file. Otherwise the value is dropped,
// and a --password source or secrets: value without a user is reported to the
// warning handler. secrets: values of the TLS options are fetched only with
// --tls-enable.
// --password must be at most 63 bytes and --tls-keyfile-password at most 1024
// bytes, whatever their source. Errors name the option, or the config file key
// when the value came from the config file.
func (af *AerospikeFlags) ResolveSecrets(ctx context.Context, sa *SecretAgentFlags) error {
	if !af.secretRefs.tracked {
		return errSecretsNotTracked
	}

	passwords := af.passwordOptions()

	for _, password := range passwords {
		if !password.used {
			af.dropPassword(password)
		}
	}

	if err := af.fetchSecrets(ctx, sa); err != nil {
		return err
	}

	for _, password := range passwords {
		if password.used {
			if err := password.read(); err != nil {
				return err
			}
		}
	}

	return nil
}

// SetWarningHandler sets the function ResolveSecrets passes warnings to, such
// as a --password source that is ignored because no user is set. Without one,
// warnings are written to standard error after "Warning: ".
func (af *AerospikeFlags) SetWarningHandler(handler func(msg string)) {
	af.secretRefs.warn = handler
}

func (af *AerospikeFlags) fetchSecrets(ctx context.Context, sa *SecretAgentFlags) error {
	var client *secretagent.Client

	for _, target := range af.secretTargets() {
		if !*target.isRef || (strings.HasPrefix(target.name, "tls-") && !af.TLSEnable) {
			continue
		}

		if client == nil {
			var err error

			if client, err = sa.NewClient(); err != nil {
				return err
			}
		}

		secret, err := client.Resolve(ctx, target.ref)
		if err != nil {
			return fmt.Errorf("%s: %w", af.optionLabel(target.name), err)
		}

		target.set(secret)
		*target.isRef = false
	}

	return nil
}

func (af *AerospikeFlags) dropPassword(password passwordOption) {
	source := *password.isRef || (*password.unread && hasPasswordSource(string(*password.value)))
	if password.warnIgnored && source {
		af.warn(password.label + ": ignored because no user is set")
	}

	*password.value = nil
	*password.isRef = false
	*password.unread = false
}

func (af *AerospikeFlags) warn(msg string) {
	if af.secretRefs.warn != nil {
		af.secretRefs.warn(msg)
		return
	}

	fmt.Fprintln(os.Stderr, "Warning: "+msg)
}

// optionLabel names a flag in messages: the option when it was given on the
// command line, which always beats the config file, and the config file key
// otherwise.
func (af *AerospikeFlags) optionLabel(name string) string {
	if af.secretRefs.flagSet.Changed(name) {
		return "--" + name
	}

	return name + " in config file"
}

type secretRefs struct {
	flagSet                                                            *pflag.FlagSet
	warn                                                               func(msg string)
	user, password, tlsCAFile, tlsCertFile, tlsKeyFile, tlsKeyFilePass bool
	unreadPassword, unreadTLSKeyFilePass                               bool
	tracked                                                            bool
}

// passwordOption is --password or --tls-keyfile-password. unread is set while
// value holds the command line or config file text, which read resolves.
type passwordOption struct {
	value       *PasswordFlag
	isRef       *bool
	unread      *bool
	label       string
	maxLen      int
	used        bool
	firstLine   bool
	warnIgnored bool
}

func (af *AerospikeFlags) passwordOptions() []passwordOption {
	pki := af.AuthMode == AuthModeFlag(as.AuthModePKI)

	return []passwordOption{
		{
			value:       &af.Password,
			isRef:       &af.secretRefs.password,
			unread:      &af.secretRefs.unreadPassword,
			label:       af.optionLabel("password"),
			maxLen:      passwordMaxLen,
			used:        af.User != "" && !pki,
			warnIgnored: af.User == "" && !pki,
		},
		{
			value:     &af.TLSKeyFilePass,
			isRef:     &af.secretRefs.tlsKeyFilePass,
			unread:    &af.secretRefs.unreadTLSKeyFilePass,
			label:     af.optionLabel("tls-keyfile-password"),
			maxLen:    tlsKeyFilePasswordMaxLen,
			used:      len(af.TLSKeyFile) != 0,
			firstLine: true,
		},
	}
}

// read resolves an unread value. A value fetched from the Secret Agent is used
// as is and only checked for NUL bytes and length.
func (p passwordOption) read() error {
	if !*p.unread {
		if err := checkNoNUL(p.label, string(*p.value)); err != nil {
			return err
		}

		return checkPasswordLen(p.label, "password", string(*p.value), p.maxLen)
	}

	password, err := readPassword(p.label, string(*p.value), p.maxLen, p.firstLine)
	if err != nil {
		return err
	}

	*p.value = PasswordFlag(password)
	*p.unread = false

	return nil
}

func (af *AerospikeFlags) secretTargets() []secretTarget {
	keyFilePass := newSecretTarget("tls-keyfile-password", &af.TLSKeyFilePass, &af.secretRefs.tlsKeyFilePass,
		&af.secretRefs.unreadTLSKeyFilePass)
	keyFilePass.trim = true

	return []secretTarget{
		newSecretTarget("user", &af.User, &af.secretRefs.user, nil),
		newSecretTarget("password", &af.Password, &af.secretRefs.password, &af.secretRefs.unreadPassword),
		newSecretTarget("tls-cafile", &af.TLSRootCAFile, &af.secretRefs.tlsCAFile, nil),
		newSecretTarget("tls-certfile", &af.TLSCertFile, &af.secretRefs.tlsCertFile, nil),
		newSecretTarget("tls-keyfile", &af.TLSKeyFile, &af.secretRefs.tlsKeyFile, nil),
		keyFilePass,
	}
}

// trackSecretRefs wraps the flags ResolveSecrets reads. A secrets: value is
// stored as is, and the wrapper records whether the raw text was a reference,
// because b64:, env: and file: values of the other flags are stored after
// expansion. --password stores every value as is and --tls-keyfile-password
// with surrounding whitespace trimmed, for ResolveSecrets to read once the
// user, auth mode and key file are known.
func (af *AerospikeFlags) trackSecretRefs(f *pflag.FlagSet) {
	for _, target := range af.secretTargets() {
		flag := f.Lookup(target.name)
		flag.Value = &secretRefValue{
			Value: flag.Value, isRef: target.isRef, unread: target.unread, setRaw: target.set, trim: target.trim,
		}
	}

	af.secretRefs.flagSet = f
	af.secretRefs.tracked = true
}

type secretRefValue struct {
	pflag.Value
	isRef  *bool
	unread *bool
	setRaw func(string)
	trim   bool
}

func (v *secretRefValue) Type() string {
	typ := v.Value.Type()
	if i := strings.LastIndexByte(typ, ','); i >= 0 {
		return typ[:i+1] + "secrets:<resource>:<key>," + typ[i+1:]
	}

	return typ
}

func (v *secretRefValue) Set(val string) error {
	if v.trim {
		val = strings.Trim(val, asciiSpace)
	}

	isRef := secretagent.IsSecret(val)

	switch {
	case v.unread != nil:
		v.setRaw(val)
		*v.unread = !isRef
	case isRef:
		v.setRaw(val)
	default:
		if err := v.Value.Set(val); err != nil {
			return err
		}
	}

	*v.isRef = isRef

	return nil
}

type secretTarget struct {
	set    func(string)
	isRef  *bool
	unread *bool
	name   string
	ref    string
	trim   bool
}

func newSecretTarget[T ~string | ~[]byte](name string, value *T, isRef, unread *bool) secretTarget {
	return secretTarget{
		set:    func(secret string) { *value = T(secret) },
		isRef:  isRef,
		unread: unread,
		name:   name,
		ref:    string(*value),
	}
}
