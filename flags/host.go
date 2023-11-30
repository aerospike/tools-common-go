package flags

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

const (
	DEFAULT_PORT = 3000
	DEFAULT_IPV4 = "127.0.0.1"
)

type HostTLSPort struct {
	Host    string
	TLSName string
	Port    int
}

func (addr *HostTLSPort) String() string {
	str := addr.Host

	if addr.TLSName != "" {
		str = fmt.Sprintf("%s:%s", str, addr.TLSName)
	}

	if addr.Port != 0 {
		str = fmt.Sprintf("%s:%v", str, addr.Port)
	}

	return str
}

func NewDefaultHostTLSPort() *HostTLSPort {
	return &HostTLSPort{
		DEFAULT_IPV4,
		"",
		DEFAULT_PORT,
	}
}

type HostTLSPortSlice []*HostTLSPort

func (slice *HostTLSPortSlice) String() string {
	strs := []string{}

	for _, elem := range *slice {
		strs = append(strs, elem.String())
	}

	if len(strs) == 1 {
		return strs[0]
	}

	str := fmt.Sprintf("[%s]", strings.Join(strs, ", "))

	return str
}

// A cobra PFlag to parse and display help info for the host[:tls-name][:port]
// input option.  It implements the pflag Value and SliceValue interfaces to
// enable automatic parsing by cobra.
type HostTLSPortSliceFlag struct {
	default_ bool
	Seeds    HostTLSPortSlice
}

func NewHostTLSPortSliceFlag() HostTLSPortSliceFlag {
	return HostTLSPortSliceFlag{
		default_: true,
		Seeds: HostTLSPortSlice{
			NewDefaultHostTLSPort(),
		},
	}

}

func parseHostTLSPort(v string) (*HostTLSPort, error) {
	host := &HostTLSPort{}
	ipv6HostPattern := `^\[(?P<host>.*)\]`
	hostPattern := `^(?P<host>[^:]*)` // matched ipv4 and hostname
	tlsNamePattern := `(?P<tlsName>.*)`
	portPattern := `(?P<port>\d+)$`
	re_ipv6host := regexp.MustCompile(fmt.Sprintf("%s$", ipv6HostPattern))
	re_ipv6hostport := regexp.MustCompile(fmt.Sprintf("%s:%s", ipv6HostPattern, portPattern))
	re_ipv6hostnameport := regexp.MustCompile(fmt.Sprintf("%s:%s:%s", ipv6HostPattern, tlsNamePattern, portPattern))
	re_ipv4host := regexp.MustCompile(fmt.Sprintf("%s$", hostPattern))
	re_ipv4hostport := regexp.MustCompile(fmt.Sprintf("%s:%s", hostPattern, portPattern))
	re_ipv4hostnameport := regexp.MustCompile(fmt.Sprintf("%s:%s:%s", hostPattern, tlsNamePattern, portPattern))

	regexsAndNames := []struct {
		regex      *regexp.Regexp
		groupNames []string
	}{
		// The order is important since the ipv4 pattern also matches ipv6
		{re_ipv6hostnameport, re_ipv6hostnameport.SubexpNames()},
		{re_ipv6hostport, re_ipv6hostport.SubexpNames()},
		{re_ipv6host, re_ipv6host.SubexpNames()},
		{re_ipv4hostnameport, re_ipv4hostnameport.SubexpNames()},
		{re_ipv4hostport, re_ipv4hostport.SubexpNames()},
		{re_ipv4host, re_ipv4host.SubexpNames()},
	}

	for _, r := range regexsAndNames {
		regex := r.regex
		groupNames := r.groupNames
		if matchs := regex.FindStringSubmatch(v); matchs != nil {
			for idx, match := range matchs {
				name := groupNames[idx]
				var err error

				switch {
				case name == "host":
					host.Host = match
				case name == "tlsName":
					host.TLSName = match
				case name == "port":
					var int_ int64
					int_, err = strconv.ParseInt(match, 0, 0)

					if err == nil {
						host.Port = int(int_)
					}
				}

				if err != nil {
					return host, fmt.Errorf("failed to parse %s : %s", name, err)
				}
			}
			return host, nil
		}
	}

	return host, fmt.Errorf("does not match any expected formats")
}

// Append adds the specified value to the end of the flag value list.
func (slice *HostTLSPortSliceFlag) Append(val string) error {
	host, err := parseHostTLSPort(val)

	if err != nil {
		return err
	}

	slice.Seeds = append(slice.Seeds, host)
	return nil
}

// Replace will fully overwrite any data currently in the flag value list.
func (slice *HostTLSPortSliceFlag) Replace(vals []string) error {
	slice.Seeds = HostTLSPortSlice{}

	for _, val := range vals {
		if err := slice.Append(val); err != nil {
			return err
		}
	}

	return nil
}

// GetSlice returns the flag value list as an array of strings.
func (slice *HostTLSPortSliceFlag) GetSlice() []string {
	strs := []string{}

	for _, elem := range slice.Seeds {
		strs = append(strs, elem.String())
	}

	return strs
}

func (slice *HostTLSPortSliceFlag) Set(commaSepVal string) error {
	vals := strings.Split(commaSepVal, ",")

	if slice.default_ {
		slice.default_ = false
		return slice.Replace(vals)
	}

	for _, val := range vals {
		if err := slice.Append(val); err == nil {
			return err
		}
	}

	return nil
}

func (slice *HostTLSPortSliceFlag) Type() string {
	return "host[:tls-name][:port][,...]"
}

func (slice *HostTLSPortSliceFlag) String() string {
	if slice.default_ {
		// displayed in help
		return DEFAULT_IPV4
	}

	return slice.Seeds.String()
}
