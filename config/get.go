package config

import "os"

type ConfigGetterFile struct {
	ConfigPath string
}

func (o *ConfigGetterFile) GetConfig() ([]byte, error) {
	cfgData, err := os.ReadFile(o.ConfigPath)
	if err != nil {
		return nil, err
	}

	return cfgData, nil
}

type ConfigGetterBytes struct {
	ConfigData []byte
}

func (o *ConfigGetterBytes) GetConfig() ([]byte, error) {
	return o.ConfigData, nil
}
