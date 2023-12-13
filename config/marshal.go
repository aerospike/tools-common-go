package config

import (
	"github.com/pelletier/go-toml/v2"
	"gopkg.in/yaml.v3"
)

// UnmarshallerTOML defines a config Unmarshaller for TOML.
type UnmarshallerTOML struct{}

// NewUnmarshallerTOML returns a new UnmarshallerTOML
func NewUnmarshallerTOML() *UnmarshallerTOML {
	return &UnmarshallerTOML{}
}

// Unmarshal unmarshals TOML format text into v.
func (o *UnmarshallerTOML) Unmarshal(data []byte, v any) error {
	err := toml.Unmarshal(data, v)
	if err != nil {
		return err
	}

	return nil
}

// UnmarshallerYAML defines a config Unmarshaller for YAML.
type UnmarshallerYAML struct{}

// NewUnmarshallerYAML returns a new UnmarshallerYAML
func NewUnmarshallerYAML() *UnmarshallerYAML {
	return &UnmarshallerYAML{}
}

// Unmarshal unmarshals YAML format text into v.
func (o *UnmarshallerYAML) Unmarshal(data []byte, v any) error {
	err := yaml.Unmarshal(data, v)
	if err != nil {
		return err
	}

	return nil
}
