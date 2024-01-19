package config2

import (
	"fmt"
	"strings"

	"github.com/aerospike/tools-common-go/client"
	"github.com/aerospike/tools-common-go/flags"
	"github.com/mitchellh/mapstructure"
	"github.com/spf13/viper"
)

type Config struct {
	cluster *client.AerospikeConfig
}

// // Indicated that a flag is located in the "cluster" toml context.
// // A map is being used as a set in this case.
// var clusterConfigs = map[string]int8{
// 	"host":                 0,
// 	"port":                 0,
// 	"user":                 0,
// 	"password":             0,
// 	"auth":                 0,
// 	"tls-name":             0,
// 	"tls-enable":           0,
// 	"tls-certfile":         0,
// 	"tls-keyfile":          0,
// 	"tls-keyfile-password": 0,
// 	"tls-cafile":           0,
// 	"tls-capath":           0,
// 	"tls-protocols":        0,
// }

// // Indicated that a flag is located in the "uda" toml context
// // A map is being used as a set in this case.
// var udaConfigs = map[string]int8{
// 	"agent-port": 0,
// 	"store-file": 0,
// }

// initConfig reads in config file and ENV variables if set.
func InitConfig(cfgFile string, instance string, clusterConfig *Config) (string, error) {
	decoderConfigs := []viper.DecoderConfigOption{
		func(dc *mapstructure.DecoderConfig) {
			dc.MatchName = func(mapKey, fieldName string) bool {
				if instance == "" {
					return strings.EqualFold(mapKey, fieldName)
				}

				splitMapKey := strings.Split(mapKey, ".")

				if len(splitMapKey) <= 1 {
					return strings.EqualFold(mapKey, fieldName)
				}

				topLevel := splitMapKey[0]
				topLevel += "_" + instance
				strings.Join(splitMapKey[1:], ".")
				mapKey = topLevel + "." + mapKey

				return strings.EqualFold(mapKey, fieldName)
			}
		},
		viper.DecodeHook(flags.AuthModeFlagHookFunc()),
		viper.DecodeHook(flags.CertFlagHookFunc()),
		viper.DecodeHook(flags.HostTLSPortSliceFlagHookFunc()),
		viper.DecodeHook(flags.PasswordFlagHookFunc()),
		viper.DecodeHook(flags.TLSProtocolFlagHookFunc()),
	}

	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		viper.AddConfigPath(ASTOOLS_CONF_DIR)
		viper.SetConfigName(ASTOOLS_CONF_NAME)
	}

	var configFileUsed string

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		configFileUsed = viper.ConfigFileUsed()
	} else {
		// If .conf then explicitly set type to toml.
		viper.SetConfigType("toml")
		if err := viper.ReadInConfig(); err == nil {
			configFileUsed = viper.ConfigFileUsed()
		} else if cfgFile != "" {
			return "", fmt.Errorf("failed to read config file: %w", err)
		}
	}

	viper.Unmarshal(clusterConfig, decoderConfigs...)

	if configFileUsed == "" {
		return "", nil
	}

	return configFileUsed, nil
}
