package config

import "os"

// Getter is an interface for getting
// config file text
type Getter interface {
	GetConfig() ([]byte, error)
}

// GetterFile defines a config getter that retrieves
// config data from a file.
type GetterFile struct {
	ConfigPath string
}

// NewGetterFile returns a new GetterFile
// using the passed config file path
func NewGetterFile(configPath string) *GetterFile {
	return &GetterFile{ConfigPath: configPath}
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

// NewGetterBytes returns a new GetterBytes
// using the passed in config data.
func NewGetterBytes(data []byte) *GetterBytes {
	return &GetterBytes{ConfigData: data}
}

// GetConfig loads and returns config text from a byte slice.
func (o *GetterBytes) GetConfig() ([]byte, error) {
	return o.ConfigData, nil
}
