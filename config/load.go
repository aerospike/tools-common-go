package config

import (
	"errors"
	"fmt"
	"path/filepath"
)

// CFGLoader defines an interface for loading
// config files.
type CFGLoader interface {
	Load(v any) error
}

// Loader is a struct used to get
// and unmarshal config data
type Loader struct {
	Getters       []Getter
	Unmarshallers []Unmarshaller
}

// NewToolsConfigLoaderFile creates a new ConfigLoader with config
// getters and unmarshalers matching what the Aerospike Tools config files support.
func NewToolsConfigLoaderFile(configPath string) *Loader {
	loader := &Loader{
		Getters: []Getter{
			&GetterFile{
				ConfigPath: configPath,
			},
		},
		Unmarshallers: []Unmarshaller{
			&UnmarshallerTOML{},
			&UnmarshallerYAML{},
		},
	}

	// Add the default tools file getter last. If everything else fails
	// this will try to load the default astools.conf
	loader.Getters = append(loader.Getters, &GetterFile{
		ConfigPath: filepath.Join(AsToolsConfDir, AsToolsConfName),
	})

	return loader
}

// NewLoader returns a new Loader using the
// passed in getters and unmarshallers.
func NewLoader(getters []Getter, unmarshallers []Unmarshaller) *Loader {
	return &Loader{
		Getters:       getters,
		Unmarshallers: unmarshallers,
	}
}

var (
	ErrFailedToGetConfig       = fmt.Errorf("failed to get config")
	ErrFailedToUnmarshalConfig = fmt.Errorf("failed to unmarshal config")
)

// Load gets the config from the first successful getter.Get()
// then unmarshals it using the first successful
// unmarshaller.Unmarshal
func (o *Loader) Load(v any) error {
	var (
		cfgData []byte
		err     error
	)

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
