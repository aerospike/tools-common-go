package flags

import (
	"fmt"

	"github.com/aerospike/tools-common-go/config"
	"github.com/spf13/pflag"
)

// TODO: doc string
type ConfFileFlags struct {
	File     string
	Instance string
}

func NewConfFileFlags() *ConfFileFlags {
	return &ConfFileFlags{}
}

// TODO: doc string
func (cf *ConfFileFlags) NewFlagSet(fmtUsage UsageFormatter) *pflag.FlagSet {
	f := &pflag.FlagSet{}

	f.StringVar(&cf.File, "config-file", "", fmtUsage(fmt.Sprintf("Config file (default is %s/%s)", config.AsToolsConfDir, config.AsToolsConfName)))                                                                                    //nolint:lll //Reason: Wrapping this line would make editing difficult.
	f.StringVar(&cf.Instance, "instance", "", fmtUsage("For support of the aerospike tools toml schema. Sections with the instance are read. e.g in the case where instance 'a' is specified sections 'cluster_a', 'uda_a' are read.")) //nolint:lll //Reason: Wrapping this line would make editing difficult.

	return f
}
