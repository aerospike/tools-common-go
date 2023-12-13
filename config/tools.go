package config

import (
	_ "embed"
	"fmt"
	"strings"

	"github.com/spf13/pflag"
)

// AsToolsConfDir is the default location of the directory
// holding the Aerospike tools configuration file.
const AsToolsConfDir = "/etc/aerospike"

// AsToolsConfName is the default name of the Aerospike
// Tools configuration file.
const AsToolsConfName = "astools.conf"

//go:embed schemas/cluster.json
var ToolsAerospikeClusterSchema string

// ToolsConfig defines a Config struct for handling
// Aerospike Tools configuration files.
type ToolsConfig struct {
	// Config provides base functionality for loading, refreshing
	// getting, validating, and other operations on configs.
	Config
	// Instance sets the tools config instances that this ToolsConfig
	// will load.
	Instance string
	// Sections sets the tools config sections that this ToolsConfig
	// will load.
	Sections []string
}

// NewToolsConfig returns a ToolsConfig with the passed in ConfigLoader.
// The returned ToolsConfig is configured to only load the sections and tools config instances
// that are passed in. If those arguments are nil or empty, all sections and config instances
// will be loaded.
func NewToolsConfig(cfgLoader *Loader, sections []string, cfgInstance string) *ToolsConfig {
	res := &ToolsConfig{
		Config:   *NewConfig(cfgLoader),
		Instance: cfgInstance,
		Sections: sections,
	}

	return res
}

// GetConfig returns a map representing the loaded
// tools config data.
func (o *ToolsConfig) GetConfig() (map[string]any, error) {
	err := o.Load()
	if err != nil {
		return nil, err
	}

	return o.Data, nil
}

// ValidateConfig validates the loaded tools config data
// against the passed in JSON schema.
func (o *ToolsConfig) ValidateConfig(schemas []string) error {
	err := o.Load()
	if err != nil {
		return err
	}

	return o.Config.ValidateConfig(schemas)
}

// Load loads the tools config data into ToolsConfig.Config.Data.
// The config data is filtered by tools config instance
// and config sections if they are defined in the ToolsConfig.
func (o *ToolsConfig) Load() error {
	if o.Config.Loaded {
		return nil
	}

	err := o.Config.Load()
	if err != nil {
		return err
	}

	filterInstance(o.Data, o.Instance)
	filterSections(o.Data, o.Sections)

	return nil
}

// filterInstance filters a tools config map deleting any config sections
// that don't have the _cfgInstance suffix.
func filterInstance(cfg map[string]any, cfgInstance string) {
	if cfgInstance == "" {
		return
	}

	cfgInstance = "_" + cfgInstance

	for section := range cfg {
		if !strings.HasSuffix(section, cfgInstance) {
			delete(cfg, section)
		}
	}

	for section := range cfg {
		if strings.HasSuffix(section, cfgInstance) {
			baseSection := strings.TrimSuffix(section, cfgInstance)
			cfg[baseSection] = cfg[section]
			delete(cfg, section)
		}
	}
}

// filterSections filters a tools config map deleting any sections
// that don't match the passed in sections names.
func filterSections(cfg map[string]any, sections []string) {
	if len(sections) == 0 {
		return
	}

	keys := map[string]struct{}{}
	for _, k := range sections {
		keys[k] = struct{}{}
	}

	for section := range cfg {
		if _, ok := keys[section]; !ok {
			delete(cfg, section)
		}
	}
}

// SetFlags sets flags in a pflag.FlagSet based on the loaded tools config in ToolsConfig.
// If sections is not nil or empty, only the matching tools config sections will be used
// when setting the flags. Otherwise, all loaded sections are used.
func (o *ToolsConfig) SetFlags(sections []string, flags *pflag.FlagSet) error {
	cfg, err := o.GetConfig()
	if err != nil {
		return err
	}

	// if no sections were passed in, use whatever
	// sections are set in the ToolsConfig
	if len(sections) == 0 {
		sections = o.Sections
	}

	// if the ToolsConfig has no sections, that means
	// the entire config map was loaded, so use the keys
	// from the cfg
	if len(sections) == 0 {
		for k := range cfg {
			sections = append(sections, k)
		}
	}

	mergedConf := map[string]any{}

	for _, section := range sections {
		if v, ok := cfg[section]; ok {
			switch v := v.(type) {
			case map[string]any:
				for key, val := range v {
					mergedConf[key] = val
				}
			default:
				continue
			}
		}
	}

	flags.VisitAll(func(f *pflag.Flag) {
		val, ok := mergedConf[f.Name]
		if !ok {
			return
		}

		ferr := flags.Set(f.Name, fmt.Sprintf("%v", val))
		if ferr != nil {
			err = ferr
			return
		}
	})

	return err
}
