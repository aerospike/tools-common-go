package flags

import (
	"context"
	"fmt"

	"github.com/aerospike/tools-common-go/secretagent"
)

// ResolveSecrets replaces secrets:[<resource>:]<key> values of --user,
// --password, --tls-cafile, --tls-certfile, --tls-keyfile and
// --tls-keyfile-password with values from the Secret Agent. Call it after the
// flags and the config file are parsed, so option order does not matter, and
// before NewAerospikeConfig. As in the C tools, --password is resolved only
// with a user and --tls-keyfile-password only with a key file, and fetched
// values are never parsed again.
func (af *AerospikeFlags) ResolveSecrets(ctx context.Context, sa *SecretAgentFlags) error {
	if err := sa.Validate(); err != nil {
		return err
	}

	targets := []secretTarget{
		newSecretTarget("user", &af.User, true),
		newSecretTarget("password", &af.Password, af.User != ""),
		newSecretTarget("tls-cafile", &af.TLSRootCAFile, true),
		newSecretTarget("tls-certfile", &af.TLSCertFile, true),
		newSecretTarget("tls-keyfile", &af.TLSKeyFile, true),
		newSecretTarget("tls-keyfile-password", &af.TLSKeyFilePass, len(af.TLSKeyFile) != 0),
	}

	var client *secretagent.Client

	for _, target := range targets {
		if !target.needed || !secretagent.IsSecret(target.ref) {
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
	}

	return nil
}

type secretTarget struct {
	set    func(string)
	name   string
	ref    string
	needed bool
}

func newSecretTarget[T ~string | ~[]byte](name string, value *T, needed bool) secretTarget {
	return secretTarget{
		set:    func(secret string) { *value = T(secret) },
		name:   name,
		ref:    string(*value),
		needed: needed,
	}
}
