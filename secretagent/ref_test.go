package secretagent_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aerospike/tools-common-go/secretagent"
)

func TestIsSecret(t *testing.T) {
	t.Parallel()

	require.True(t, secretagent.IsSecret(testRef))
	require.True(t, secretagent.IsSecret("secrets:"))
	require.False(t, secretagent.IsSecret("secret:res:key"))
	require.False(t, secretagent.IsSecret("env:SECRET"))
	require.False(t, secretagent.IsSecret(passwordKey))
	require.False(t, secretagent.IsSecret(""))
}

func TestParseRef(t *testing.T) {
	t.Parallel()

	tests := []struct {
		value   string
		want    secretagent.Ref
		wantErr bool
	}{
		{value: testRef, want: secretagent.Ref{Resource: testResource, Key: testKey}},
		{value: "secrets:key", want: secretagent.Ref{Key: testKey}},
		{value: "secrets:a:b:key", want: secretagent.Ref{Resource: "a:b", Key: testKey}},
		{value: "secrets::key", want: secretagent.Ref{Key: testKey}},
		{value: "secrets:arn:aws:secretsmanager:us-east-1:1:secret:db:password", want: secretagent.Ref{
			Resource: "arn:aws:secretsmanager:us-east-1:1:secret:db", Key: passwordKey,
		}},
		{value: "secrets:", wantErr: true},
		{value: "secrets:res:", wantErr: true},
		{value: "res:key", wantErr: true},
		{value: "", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			t.Parallel()

			got, err := secretagent.ParseRef(tt.value)
			if tt.wantErr {
				requireClass(t, err, secretagent.ErrInvalidConfig)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestParseRefErrorOmitsLiteral(t *testing.T) {
	t.Parallel()

	_, err := secretagent.ParseRef("hunter2")
	require.ErrorIs(t, err, secretagent.ErrInvalidConfig)
	require.NotContains(t, err.Error(), "hunter2")
}

func TestRefString(t *testing.T) {
	t.Parallel()

	for _, value := range []string{testRef, "secrets:key", "secrets:a:b:key"} {
		ref, err := secretagent.ParseRef(value)
		require.NoError(t, err)
		require.Equal(t, value, ref.String())
	}
}
