package config

import "os"

// GetterFile defines a config getter that retrieves
// config data from a file.
type GetterFile struct {
	ConfigPath string
}

// GetConfig loads and returns config text from a file.
func (o *GetterFile) GetConfig() ([]byte, error) {
	cfgData, err := os.ReadFile(o.ConfigPath)
	if err != nil {
		return nil, err
	}

	return cfgData, nil
}

// GetterBytes defines a config getter that retrieves
// config data from a byte slice.
type GetterBytes struct {
	ConfigData []byte
}

// GetConfig loads and returns config text from a byte slice.
func (o *GetterBytes) GetConfig() ([]byte, error) {
	return o.ConfigData, nil
}
