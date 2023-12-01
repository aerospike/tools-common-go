package config

import (
	_ "embed"
	"fmt"
	"strings"

	"github.com/spf13/pflag"
)

//go:embed schemas/cluster.json
var ToolsAerospikeClusterSchema string

type ToolsConfig struct {
	Config
	Instance string
	Sections []string
}

func (o *ToolsConfig) GetConfig() (map[string]any, error) {
	err := o.Load()
	if err != nil {
		return nil, err
	}

	return o.Data, nil
}

func (o *ToolsConfig) ValidateConfig(schema string) error {
	err := o.Load()
	if err != nil {
		return err
	}

	return o.Config.ValidateConfig(schema)
}

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
			base_section := strings.TrimSuffix(section, cfgInstance)
			cfg[base_section] = cfg[section]
			delete(cfg, section)
		}
	}
}

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

	merged_cfg := map[string]any{}
	for _, section := range sections {
		if v, ok := cfg[section]; ok {
			switch v := v.(type) {
			case map[string]any:
				for key, val := range v {
					merged_cfg[key] = val
				}
			default:
				continue
			}
		}
	}

	flags.VisitAll(func(f *pflag.Flag) {
		val, ok := merged_cfg[f.Name]
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

func NewToolsConfig(cfgLoader *ConfigLoader, sections []string, cfgInstance string) *ToolsConfig {
	res := &ToolsConfig{
		Config:   *NewConfig(cfgLoader),
		Instance: cfgInstance,
		Sections: sections,
	}

	return res
}
