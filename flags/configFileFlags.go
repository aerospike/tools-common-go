package flags

import (
	"fmt"

	"github.com/aerospike/tools-common-go/config"
	"github.com/spf13/pflag"
)

// ConfFileFlags represents the flags related to setting up the config file.
type ConfFileFlags struct {
	File     string // Config file read after the default ones.
	OnlyFile string // The only config file read.
	Instance string // Instance name appended to top-level context e.g. instance=tls will read from cluster_tls.
	NoFile   bool   // Read no config file.
}

func NewConfFileFlags() *ConfFileFlags {
	return &ConfFileFlags{}
}

// NewFlagSet creates a new pflag.FlagSet with the config file flags.
// The fmtUsage parameter is a function that formats the usage string.
func (cf *ConfFileFlags) NewFlagSet(fmtUsage UsageFormatter) *pflag.FlagSet {
	f := &pflag.FlagSet{}

	f.StringVar(&cf.File, "config-file", "", fmtUsage(fmt.Sprintf(
		"Read this config file after %s/%s.conf and ~/.aerospike/%[2]s.conf."+
			" A later file overrides an earlier one, key by key.", config.DefaultConfDir, config.DefaultConfName)))
	f.StringVar(&cf.OnlyFile, "only-config-file", "", fmtUsage("Read only this config file."))
	f.BoolVar(&cf.NoFile, "no-config-file", false, fmtUsage("Do not read any config file."))
	f.StringVar(&cf.Instance, "instance", "", fmtUsage("Sections with this instance are read. With instance 'a',"+
		" the sections cluster_a and secret-agent_a are read."))

	return f
}

// Files returns the config files the flags select, for config.InitConfigFiles.
func (cf *ConfFileFlags) Files() config.Files {
	return config.Files{File: cf.File, Only: cf.OnlyFile, None: cf.NoFile}
}
