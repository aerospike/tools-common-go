package config

import (
	"errors"
	"fmt"
	"path/filepath"
)

// ConfigGetter is an interface for getting
// config file text
type ConfigGetter interface {
	GetConfig() ([]byte, error)
}

// ConfigUnmarshaller is an interface for
// unmarshalling config text into a destination
type ConfigUnmarshaller interface {
	Unmarshal(data []byte, v any) error
}

// ConfigLoader is a struct used to get
// and unmarshal config data
type ConfigLoader struct {
	Getters       []ConfigGetter
	Unmarshallers []ConfigUnmarshaller
}

var (
	ErrFailedToGetConfig       = fmt.Errorf("failed to get config")
	ErrFailedToUnmarshalConfig = fmt.Errorf("failed to unmarshal config")
)

// Load gets the config from the first successful getter.Get()
// then unmarshals it using the first successful
// unmarshaller.Unmarshal
func (o *ConfigLoader) Load(v any) error {
	var cfgData []byte
	var err error

	for _, getter := range o.Getters {
		cfgData, err = getter.GetConfig()
		if err == nil {
			break
		}
	}
	if err != nil {
		return errors.Join(ErrFailedToGetConfig, err)
	}

	for _, unmarshaller := range o.Unmarshallers {
		err = unmarshaller.Unmarshal(cfgData, v)
		if err == nil {
			break
		}
	}
	if err != nil {
		return errors.Join(ErrFailedToUnmarshalConfig, err)
	}

	return nil
}

// NewToolsConfigLoaderFile creates a new ConfigLoader with config
// getters and unmarshalers matching what the Aerospike Tools config files support.
func NewToolsConfigLoaderFile(configPath string) *ConfigLoader {
	loader := &ConfigLoader{
		Getters: []ConfigGetter{
			&ConfigGetterFile{
				ConfigPath: configPath,
			},
		},
		Unmarshallers: []ConfigUnmarshaller{
			&ConfigUnmarshallerTOML{},
			&ConfigUnmarshallerYAML{},
		},
	}

	// Add the default tools file getter last. If everything else fails
	// this will try to load the default astools.conf
	loader.Getters = append(loader.Getters, &ConfigGetterFile{
		ConfigPath: filepath.Join(ASTOOLS_CONF_DIR, ASTOOLS_CONF_NAME),
	})

	return loader
}
