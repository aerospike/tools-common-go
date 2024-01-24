package flags

import "testing"

func TestConfFileFlags_NewFlagSet(t *testing.T) {
	confFileFlags := NewConfFileFlags()
	flagSet := confFileFlags.NewFlagSet(func(str string) string { return str })

	flagSet.Parse([]string{"--config-file", "test.toml", "--instance", "a"})

	if confFileFlags.File != "test.toml" {
		t.Errorf("Expected %s, got %s", "test.toml", confFileFlags.File)
	}

	if confFileFlags.Instance != "a" {
		t.Errorf("Expected %s, got %s", "a", confFileFlags.Instance)
	}
}
