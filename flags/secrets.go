package flags

import (
	"context"
	"errors"
	"fmt"

	"github.com/aerospike/tools-common-go/secretagent"
	"github.com/spf13/pflag"
)

var errSecretsNotTracked = errors.New("secret references are not tracked, use NewFlagSetWithSecrets")

// ResolveSecrets replaces secrets:[<resource>:]<key> values of --user,
// --password, --tls-cafile, --tls-certfile, --tls-keyfile and
// --tls-keyfile-password with values from the Secret Agent. The flags must come
// from NewFlagSetWithSecrets. Only values whose command line or config file
// text starts with secrets: are resolved, so a b64:, env:, env-b64: or file:
// value that expands to secrets:... stays literal. Call it after the flags and
// the config file are parsed, so option order does not matter, and before
// NewAerospikeConfig. --password is resolved only with a user and
// --tls-keyfile-password only with a key file, and fetched values are never
// parsed again.
func (af *AerospikeFlags) ResolveSecrets(ctx context.Context, sa *SecretAgentFlags) error {
	if !af.secretRefs.tracked {
		return errSecretsNotTracked
	}

	var client *secretagent.Client

	for _, target := range af.secretTargets() {
		if !target.needed || !*target.isRef {
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
			return fmt.Errorf("--%s: %w", target.name, err)
		}

		target.set(secret)
		*target.isRef = false
	}

	return nil
}

type secretRefs struct {
	user, password, tlsCAFile, tlsCertFile, tlsKeyFile, tlsKeyFilePass bool
	tracked                                                            bool
}

func (af *AerospikeFlags) secretTargets() []secretTarget {
	return []secretTarget{
		newSecretTarget("user", &af.User, &af.secretRefs.user, true),
		newSecretTarget("password", &af.Password, &af.secretRefs.password, af.User != ""),
		newSecretTarget("tls-cafile", &af.TLSRootCAFile, &af.secretRefs.tlsCAFile, true),
		newSecretTarget("tls-certfile", &af.TLSCertFile, &af.secretRefs.tlsCertFile, true),
		newSecretTarget("tls-keyfile", &af.TLSKeyFile, &af.secretRefs.tlsKeyFile, true),
		newSecretTarget("tls-keyfile-password", &af.TLSKeyFilePass, &af.secretRefs.tlsKeyFilePass,
			len(af.TLSKeyFile) != 0),
	}
}

// trackSecretRefs wraps the flags ResolveSecrets reads. A secrets: value is
// stored as is, and the wrapper records whether the raw text was a reference,
// because b64:, env: and file: values are stored after expansion.
func (af *AerospikeFlags) trackSecretRefs(f *pflag.FlagSet) {
	for _, target := range af.secretTargets() {
		flag := f.Lookup(target.name)
		flag.Value = &secretRefValue{Value: flag.Value, isRef: target.isRef, setRef: target.set}
	}

	af.secretRefs.tracked = true
}

type secretRefValue struct {
	pflag.Value
	isRef  *bool
	setRef func(string)
}

func (v *secretRefValue) Set(val string) error {
	if secretagent.IsSecret(val) {
		v.setRef(val)
		*v.isRef = true

		return nil
	}

	if err := v.Value.Set(val); err != nil {
		return err
	}

	*v.isRef = false

	return nil
}

type secretTarget struct {
	set    func(string)
	isRef  *bool
	name   string
	ref    string
	needed bool
}

func newSecretTarget[T ~string | ~[]byte](name string, value *T, isRef *bool, needed bool) secretTarget {
	return secretTarget{
		set:    func(secret string) { *value = T(secret) },
		isRef:  isRef,
		name:   name,
		ref:    string(*value),
		needed: needed,
	}
}
