package config

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/xeipuuv/gojsonschema"
)

// CFGLoader defines an interface for loading
// config files.
type CFGLoader interface {
	Load(v any) error
}

// Config is the base definition of a Config file.
// It contains config Data retrieved and unmarshaled
// by a CFGLoader.
type Config struct {
	// Data is unmarshaled config data.
	Data map[string]any
	// Loaded signifies whether Data has already been
	// loaded by Loader. All Config methods check this to
	// see if Data needs to be re-loaded before use.
	Loaded bool
	// Loader retrieves and unmarshals the config data.
	Loader CFGLoader
}

// Load loads the config data into the Config.Data.
func (o *Config) Load() error {
	if o.Loaded {
		return nil
	}

	err := o.Loader.Load(&o.Data)
	if err != nil {
		return err
	}

	o.Loaded = true
	return nil
}

// Refresh sets Config.Loaded to false, which marks the config data
// to be reloaded.
func (o *Config) Refresh() {
	o.Loaded = false
}

// GetConfig returns the config data, Config.Data.
func (o *Config) GetConfig() (map[string]any, error) {
	err := o.Load()
	if err != nil {
		return nil, err
	}

	return o.Data, nil
}

// ValidateConf validates the config data against the passed in JSON schema.
func (o *Config) ValidateConfig(schema string) error {
	confMap, err := o.GetConfig()
	if err != nil {
		return fmt.Errorf("unable to get config: %w", err)
	}

	jsonBytes, err := json.Marshal(confMap)
	if err != nil {
		return fmt.Errorf("unable to marshal map to json: %w", err)
	}

	schemaloader := gojsonschema.NewStringLoader(schema)
	confLoader := gojsonschema.NewStringLoader(string(jsonBytes))

	validResult, err := gojsonschema.Validate(schemaloader, confLoader)
	if err != nil {
		return fmt.Errorf("unable to validate config schema: %w", err)
	}

	if !validResult.Valid() {
		verrs := fmt.Errorf("invalid config file")
		for _, err := range validResult.Errors() {
			errors.Join(verrs, fmt.Errorf("- %s", err))
		}
		return verrs
	}

	return nil
}

// NewConfig returns a new config set with the passed in cfgLoader.
func NewConfig(cfgLoader *ConfigLoader) *Config {
	res := &Config{
		Loader: cfgLoader,
	}

	return res
}
