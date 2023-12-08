package config

import "os"

// ConfigGetterFile defines a config getter that retrieves
// config data from a file.
type ConfigGetterFile struct {
	ConfigPath string
}

// GetConfig loads and returns config text from a file.
func (o *ConfigGetterFile) GetConfig() ([]byte, error) {
	cfgData, err := os.ReadFile(o.ConfigPath)
	if err != nil {
		return nil, err
	}

	return cfgData, nil
}

// ConfigGetterBytes defines a config getter that retrieves
// config data from a byte slice.
type ConfigGetterBytes struct {
	ConfigData []byte
}

// GetConfig loads and returns config text from a byte slice.
func (o *ConfigGetterBytes) GetConfig() ([]byte, error) {
	return o.ConfigData, nil
}
