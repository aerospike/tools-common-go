package config

import (
	_ "embed"
	"fmt"
	"testing"

	"github.com/go-test/deep"
	"github.com/pelletier/go-toml/v2"
	"github.com/spf13/pflag"
)

var confTOML = `
# -----------------------------------
# Aerospike tools configuration file.
# -----------------------------------
[cluster]
host = "1.1.1.1:3001,2.2.2.2:3002"          
user = "default-user"
password = "default-password"
auth = "EXTERNAL"

[cluster_tls]
port = 4333
host = "3.3.3.3"
tls-name = "tls-name"
tls-enable = true
tls-capath = "root-ca-path/"
tls-cafile = "root-ca-path/root-ca.pem"
tls-certfile = "cert.pem"
tls-keyfile = "key.pem"
tls-keyfile-password = "file:key-pass.txt"

[cluster_instance]
host = "3.3.3.3:3003,4.4.4.4:3004"          
user = "test-user"
password = "test-password"

[cluster_env]
host = "5.5.5.5:env-tls-name:1000"          
password = "env:AEROSPIKE_TEST"

[cluster_envb64]
host = "6.6.6.6:env-tls-name:1000"    
password = "env-b64:AEROSPIKE_TEST"

[cluster_b64]
host = "7.7.7.7:env-tls-name:1000"          
password = "b64:dGVzdC1wYXNzd29yZAo="

[cluster_file]
host = "1.1.1.1"          
password = "file:file_test.txt"

[uda]
agent-port = 8001
store-file = "default1.store"

[uda_instance]
store-file = "test.store"
`

type mockConfigGetter struct {
	data []byte
	err  error
}

func (o *mockConfigGetter) GetConfig() ([]byte, error) {
	return o.data, o.err
}

type mockConfigUnmarshaller struct {
	err  error
	data any
}

func (o *mockConfigUnmarshaller) Unmarshal(data []byte, v any) error {
	return o.err
}

func TestToolsConfig_Load(t *testing.T) {

	confTOMLMap := map[string]any{}
	err := toml.Unmarshal([]byte(confTOML), &confTOMLMap)
	if err != nil {
		t.Error(err)
	}

	tests := []struct {
		name        string
		toolsConfig *ToolsConfig
		wantErr     bool
	}{
		{
			name: "basic positive",
			toolsConfig: NewToolsConfig(
				&Loader{
					[]Getter{
						&mockConfigGetter{
							data: []byte("hi"),
							err:  nil,
						},
					},
					[]Unmarshaller{
						&mockConfigUnmarshaller{
							err: nil,
						},
					},
				},
				[]string{},
				"",
			),
			wantErr: false,
		},
		{
			name: "basic negative",
			toolsConfig: NewToolsConfig(
				&Loader{
					[]Getter{
						&mockConfigGetter{
							data: nil,
							err:  fmt.Errorf("mock error"),
						},
					},
					[]Unmarshaller{
						&mockConfigUnmarshaller{
							err: nil,
						},
					},
				},

				[]string{},
				"",
			),
			wantErr: true,
		},
		{
			name: "filter instance and sections positive",
			toolsConfig: NewToolsConfig(

				&Loader{
					[]Getter{
						&GetterBytes{
							ConfigData: []byte(confTOML),
						},
					},
					[]Unmarshaller{
						&UnmarshallerTOML{},
					},
				},
				[]string{"cluster", "missing_section"},
				"instance",
			),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.toolsConfig.Load(); (err != nil) != tt.wantErr {
				t.Errorf("ToolsConfig.Load() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestToolsConfig_SetFlags(t *testing.T) {
	type testToolsFlags struct {
		Host      string
		Port      int
		StoreFile string
		NotInFile int
	}

	confVals := testToolsFlags{}
	flags := pflag.NewFlagSet("testFlags", pflag.PanicOnError)
	flags.StringVar(&confVals.Host, "host", "", "hostname")
	flags.IntVar(&confVals.Port, "port", 3000, "port")
	flags.StringVar(&confVals.StoreFile, "store-file", "testval", "uda section store-file")
	flags.IntVar(&confVals.NotInFile, "not-in-file", -1, "value not present in the tools config file")

	type args struct {
		sections []string
		flags    *pflag.FlagSet
	}
	tests := []struct {
		name        string
		toolsConfig *ToolsConfig
		args        args
		wantErr     bool
		want        testToolsFlags
	}{
		{
			name: "basic positive",
			toolsConfig: NewToolsConfig(
				&Loader{
					[]Getter{
						&GetterBytes{
							ConfigData: []byte(confTOML),
						},
					},
					[]Unmarshaller{
						&UnmarshallerTOML{},
					},
				},
				nil,
				"",
			),
			args: args{
				flags: flags,
				sections: []string{
					"cluster",
					"uda",
				},
			},
			wantErr: false,
			want: testToolsFlags{
				Host:      "1.1.1.1:3001,2.2.2.2:3002",
				Port:      3000,
				NotInFile: -1,
				StoreFile: "default1.store",
			},
		},
		{
			name: "instance filtering positive",
			toolsConfig: NewToolsConfig(
				&Loader{
					[]Getter{
						&GetterBytes{
							ConfigData: []byte(confTOML),
						},
					},
					[]Unmarshaller{
						&UnmarshallerTOML{},
					},
				},
				nil,
				"instance",
			),
			args: args{
				sections: nil,
				flags:    flags,
			},
			wantErr: false,
			want: testToolsFlags{
				Host:      "3.3.3.3:3003,4.4.4.4:3004",
				Port:      3000,
				NotInFile: -1,
				StoreFile: "test.store",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.toolsConfig.SetFlags(tt.args.sections, tt.args.flags); (err != nil) != tt.wantErr {
				t.Errorf("ToolsConfig.SetFlags() error = %v, wantErr %v", err, tt.wantErr)
			}
			if diff := deep.Equal(confVals, tt.want); diff != nil {
				t.Error(diff)
			}
		})
	}
}

func TestToolsConfig_GetConfig(t *testing.T) {

	expTOML := map[string]any{}
	toml.Unmarshal([]byte(confTOML), &expTOML)

	tests := []struct {
		name        string
		toolsConfig *ToolsConfig
		want        map[string]any
		wantErr     bool
	}{
		{
			name: "get entire config positive",
			toolsConfig: NewToolsConfig(
				&Loader{
					[]Getter{
						&GetterBytes{
							ConfigData: []byte(confTOML),
						},
					},
					[]Unmarshaller{
						&UnmarshallerTOML{},
					},
				},
				nil,
				"",
			),
			want:    expTOML,
			wantErr: false,
		},
		{
			name: "get config by instance positive",
			toolsConfig: NewToolsConfig(
				&Loader{
					[]Getter{
						&GetterBytes{
							ConfigData: []byte(confTOML),
						},
					},
					[]Unmarshaller{
						&UnmarshallerTOML{},
					},
				},
				nil,
				"instance",
			),
			want: map[string]any{
				"cluster": map[string]any{
					"host":     "3.3.3.3:3003,4.4.4.4:3004",
					"user":     "test-user",
					"password": "test-password",
				},
				"uda": map[string]any{
					"store-file": "test.store",
				},
			},
			wantErr: false,
		},
		{
			name: "get config by instance and sections positive",
			toolsConfig: NewToolsConfig(
				&Loader{
					[]Getter{
						&GetterBytes{
							ConfigData: []byte(confTOML),
						},
					},
					[]Unmarshaller{
						&UnmarshallerTOML{},
					},
				},
				[]string{"uda"},
				"instance",
			),
			want: map[string]any{
				"uda": map[string]any{
					"store-file": "test.store",
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.toolsConfig.GetConfig()
			if (err != nil) != tt.wantErr {
				t.Errorf("ToolsConfig.GetConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := deep.Equal(got, tt.want); diff != nil {
				t.Error(diff)
			}
		})
	}
}

func TestToolsConfig_ValidateConfig(t *testing.T) {
	testConfig := NewToolsConfig(
		&Loader{
			[]Getter{
				&GetterBytes{
					ConfigData: []byte(confTOML),
				},
			},
			[]Unmarshaller{
				&UnmarshallerTOML{},
			},
		},
		nil,
		"",
	)

	type args struct {
		schemas []string
	}
	tests := []struct {
		name        string
		toolsConfig *ToolsConfig
		args        args
		wantErr     bool
	}{
		{
			name:        "basic positive",
			toolsConfig: testConfig,
			args: args{
				schemas: []string{ToolsAerospikeClusterSchema},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.toolsConfig.ValidateConfig(tt.args.schemas); (err != nil) != tt.wantErr {
				t.Errorf("ToolsConfig.ValidateConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
