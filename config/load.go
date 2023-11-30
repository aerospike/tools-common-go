package config

import (
	"errors"
	"fmt"
	"path/filepath"
)

type ConfigGetter interface {
	GetConfig() ([]byte, error)
}

type ConfigUnmarshaller interface {
	Unmarshal(data []byte, v any) error
}

type ConfigLoader struct {
	Getters       []ConfigGetter
	Unmarshallers []ConfigUnmarshaller
}

var (
	ErrFailedToGetConfig       = fmt.Errorf("failed to get config")
	ErrFailedToUnmarshalConfig = fmt.Errorf("failed to unmarshal config")
)

// Load gets the config from the first successful getter.Get()
// then it unmarshals the returned bytes using the first successful
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

func NewDefaultConfigLoaderFile(configPath string) *ConfigLoader {
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
