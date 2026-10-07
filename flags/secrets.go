package flags

import (
	"context"
	"fmt"

	"github.com/aerospike/tools-common-go/secretagent"
)

// ResolveSecrets replaces secrets:[<resource>:]<key> values of --password and
// --tls-keyfile-password with values from the Secret Agent. Call it after the
// flags and the config file are parsed, so option order does not matter. As in
// the C tools, --password is resolved only with a user and
// --tls-keyfile-password only with a key file, and fetched values are never
// parsed again.
func (af *AerospikeFlags) ResolveSecrets(ctx context.Context, sa *SecretAgentFlags) error {
	if err := sa.Validate(); err != nil {
		return err
	}

	targets := []struct {
		value  *PasswordFlag
		name   string
		needed bool
	}{
		{value: &af.Password, name: "password", needed: af.User != ""},
		{value: &af.TLSKeyFilePass, name: "tls-keyfile-password", needed: len(af.TLSKeyFile) != 0},
	}

	var client *secretagent.Client

	for _, target := range targets {
		ref := string(*target.value)
		if !target.needed || !secretagent.IsSecret(ref) {
			continue
		}

		if client == nil {
			var err error

			if client, err = sa.NewClient(); err != nil {
				return err
			}
		}

		secret, err := client.Resolve(ctx, ref)
		if err != nil {
			return fmt.Errorf("--%s: %w", target.name, err)
		}

		*target.value = PasswordFlag(secret)
	}

	return nil
}
