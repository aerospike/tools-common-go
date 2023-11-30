package config

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/xeipuuv/gojsonschema"
)

//go:embed schemas/cluster.json
var BaseSchema string

const ASTOOLS_CONF_DIR = "/etc/aerospike"
const ASTOOLS_CONF_NAME = "astools.conf"

type CFGLoader interface {
	Load(v any) error
}

type Config struct {
	Data   map[string]any
	Loaded bool
	Loader CFGLoader
}

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

func (o *Config) Refresh() {
	o.Loaded = false
}

func (o *Config) GetConfig() (map[string]any, error) {
	err := o.Load()
	if err != nil {
		return nil, err
	}

	return o.Data, nil
}

// ValidateConf loads a astools configuration using
// cfgLoader then validates it against the passed in json schema.
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

func NewConfig(cfgLoader *ConfigLoader) *Config {
	res := &Config{
		Loader: cfgLoader,
	}

	return res
}
