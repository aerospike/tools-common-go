package flags

import (
	"testing"

	"github.com/aerospike/tools-common-go/config"
	"github.com/stretchr/testify/require"
)

func TestConfFileFlags_NewFlagSet(t *testing.T) {
	confFileFlags := NewConfFileFlags()
	flagSet := confFileFlags.NewFlagSet(func(str string) string { return str })

	err := flagSet.Parse([]string{
		"--config-file", "test.toml", "--only-config-file", "only.conf", "--no-config-file", "--instance", "a",
	})
	require.NoError(t, err)

	require.Equal(t, "test.toml", confFileFlags.File)
	require.Equal(t, "only.conf", confFileFlags.OnlyFile)
	require.True(t, confFileFlags.NoFile)
	require.Equal(t, "a", confFileFlags.Instance)
	require.Equal(t, config.Files{File: "test.toml", Only: "only.conf", None: true}, confFileFlags.Files())
}

func TestConfFileFlagsDefaults(t *testing.T) {
	confFileFlags := NewConfFileFlags()
	flagSet := confFileFlags.NewFlagSet(func(str string) string { return str })

	require.NoError(t, flagSet.Parse(nil))
	require.Equal(t, config.Files{}, confFileFlags.Files())
}

func TestConfFileFlagsUsage(t *testing.T) {
	usage := NewConfFileFlags().NewFlagSet(func(str string) string { return str }).FlagUsages()

	for _, want := range []string{
		"--config-file string",
		"Read this config file after /etc/aerospike/astools.conf and ~/.aerospike/astools.conf." +
			" A later file overrides an earlier one, key by key.",
		"--only-config-file string",
		"Read only this config file.",
		"--no-config-file",
		"Do not read any config file.",
		"--instance string",
		"Sections with this instance are read. With instance 'a', the sections cluster_a and" +
			" secret-agent_a are read.",
	} {
		require.Contains(t, usage, want)
	}

	require.NotContains(t, usage, "uda")
}

func TestConfFileFlagsRejectEmptyPath(t *testing.T) {
	for _, option := range []string{"--config-file", "--only-config-file"} {
		t.Run(option, func(t *testing.T) {
			flagSet := NewConfFileFlags().NewFlagSet(func(str string) string { return str })

			err := flagSet.Parse([]string{option, ""})
			require.EqualError(t, err, `invalid argument "" for "`+option+`" flag: expected a path`)
		})
	}
}
