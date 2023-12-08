package config

import (
	"github.com/pelletier/go-toml/v2"
	"gopkg.in/yaml.v3"
)

// ConfigUnmarshallerTOML defines a config Unmarshaller for TOML.
type ConfigUnmarshallerTOML struct{}

// Unmarshal unmarshals TOML format text into v.
func (o *ConfigUnmarshallerTOML) Unmarshal(data []byte, v any) error {
	err := toml.Unmarshal(data, v)
	if err != nil {
		return err
	}

	return nil
}

// ConfigUnmarshallerYAML defines a config Unmarshaller for YAML.
type ConfigUnmarshallerYAML struct{}

// Unmarshal unmarshals YAML format text into v.
func (o *ConfigUnmarshallerYAML) Unmarshal(data []byte, v any) error {
	err := yaml.Unmarshal(data, v)
	if err != nil {
		return err
	}

	return nil
}
