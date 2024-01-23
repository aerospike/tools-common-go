package config2

import (
	"fmt"
	"strings"

	"github.com/aerospike/tools-common-go/flags"
	"github.com/mitchellh/mapstructure"
	"github.com/spf13/viper"
)

type Config struct {
	Cluster *flags.AerospikeFlags
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
func InitConfig(cfgFile string, instance string, clusterConfig *Config, otherConfigs ...any) (string, error) {
	if instance != "" {
		for _, key := range viper.AllKeys() {
			splitKey := strings.Split(key, ".")

			if len(splitKey) <= 1 {
				continue
			}

			topLevel := splitKey[0]
			topLevel += "_" + instance
			splitKey[0] = topLevel
			newKey := strings.Join(splitKey, ".")

			viper.RegisterAlias(key, newKey)
		}
	}

	decoderConfigs := []viper.DecoderConfigOption{
		viper.DecodeHook(
			mapstructure.ComposeDecodeHookFunc(
				flags.AuthModeFlagHookFunc(),
				flags.CertFlagHookFunc(),
				flags.HostTLSPortSliceFlagHookFunc(),
				flags.PasswordFlagHookFunc(),
				flags.TLSProtocolFlagHookFunc()),
		),
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

	otherConfigs = append(otherConfigs, clusterConfig)

	for _, cfg := range otherConfigs {
		err := viper.Unmarshal(cfg, decoderConfigs...)
		if err != nil {
			return "", fmt.Errorf("failed to unmarshal config: %w", err)
		}
	}

	if configFileUsed == "" {
		return "", nil
	}

	return configFileUsed, nil
}
