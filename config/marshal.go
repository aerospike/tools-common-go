package config

import (
	"github.com/pelletier/go-toml/v2"
	"gopkg.in/yaml.v3"
)

type ConfigUnmarshallerTOML struct{}

func (o *ConfigUnmarshallerTOML) Unmarshal(data []byte, v any) error {
	err := toml.Unmarshal(data, v)
	if err != nil {
		return err
	}

	return nil
}

type ConfigUnmarshallerYAML struct{}

func (o *ConfigUnmarshallerYAML) Unmarshal(data []byte, v any) error {
	err := yaml.Unmarshal(data, v)
	if err != nil {
		return err
	}

	return nil
}
