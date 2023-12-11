package config

import (
	_ "embed"
	"path/filepath"
	"testing"

	"github.com/go-test/deep"
)

const (
	testConfigPath = "./testdata/configs"
)

func Test_Config_GetConfig(t *testing.T) {

	basicResTOML := map[string]any{
		"cluster": map[string]any{
			"host":       "localhost:3000",
			"port":       int64(3000), //go-toml unmarshals int as int64
			"tls-enable": false,
			"user":       "",
		},
		"other": map[string]any{
			"outputmode": "table",
		},
	}

	basicResYAML := map[string]any{
		"cluster": map[string]any{
			"host":       "localhost:3000",
			"port":       3000,
			"tls-enable": false,
			"user":       "",
		},
		"other": map[string]any{
			"outputmode": "table",
		},
	}

	type args struct {
		cfgPath string
	}
	tests := []struct {
		name    string
		want    any
		wantErr bool
		config  *Config
	}{
		{
			name: "basic toml",
			config: NewConfig(
				NewToolsConfigLoaderFile(filepath.Join(testConfigPath, "basic.toml")),
			),
			want:    basicResTOML,
			wantErr: false,
		},
		{
			name: "basic yaml",
			config: NewConfig(
				NewToolsConfigLoaderFile(filepath.Join(testConfigPath, "basic.yaml")),
			),
			want:    basicResYAML,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.config.GetConfig()
			if (err != nil) != tt.wantErr {
				t.Errorf("getConfigMap() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := deep.Equal(got, tt.want); diff != nil {
				t.Error(diff)
			}
		})
	}
}

func Test_Config_ValidateConf(t *testing.T) {

	basicTOMLPath := filepath.Join(testConfigPath, "basic.toml")
	fileLoaderTOML := NewToolsConfigLoaderFile(basicTOMLPath)

	basicYAMLPath := filepath.Join(testConfigPath, "basic.yaml")
	fileLoaderYAML := NewToolsConfigLoaderFile(basicYAMLPath)

	failsLoader := ConfigLoader{
		Getters: []ConfigGetter{
			&ConfigGetterFile{
				ConfigPath: "badpath",
			},
		},
	}

	failsValidationLoader := ConfigLoader{
		Getters: []ConfigGetter{
			&ConfigGetterBytes{
				ConfigData: []byte("[cluster]\nhost=1234"),
			},
		},
		Unmarshallers: []ConfigUnmarshaller{
			&ConfigUnmarshallerTOML{},
		},
	}

	type args struct {
		schemas []string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
		config  *Config
	}{
		{
			name: "passes validation, toml",
			args: args{
				schemas: []string{ToolsAerospikeClusterSchema},
			},
			wantErr: false,
			config:  NewConfig(fileLoaderTOML),
		},
		{
			name: "passes validation, yaml",
			args: args{
				schemas: []string{ToolsAerospikeClusterSchema, ToolsAerospikeClusterSchema},
			},
			wantErr: false,
			config:  NewConfig(fileLoaderYAML),
		},
		{
			name: "fails validation, toml",
			args: args{
				schemas: []string{ToolsAerospikeClusterSchema},
			},
			wantErr: true,
			config:  NewConfig(&failsValidationLoader),
		},
		{
			name: "fails to load",
			args: args{
				schemas: []string{ToolsAerospikeClusterSchema},
			},
			wantErr: true,
			config:  NewConfig(&failsLoader),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.config.ValidateConfig(tt.args.schemas); (err != nil) != tt.wantErr {
				t.Errorf("ValidateConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
