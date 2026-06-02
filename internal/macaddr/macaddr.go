package macaddr

import (
	"fmt"
	"net"
	"strings"
)

type Analysis struct {
	Address     string
	Vendor      string
	IsPrivate   bool
	IsMulticast bool
}

var ouiVendors = map[string]string{
	"001A11": "Google",
	"001B63": "Apple",
	"001C42": "Parallels",
	"002248": "Microsoft",
	"002500": "Apple",
	"3C5A37": "Samsung",
	"3C7C3F": "Apple",
	"44D9E7": "Ubiquiti",
	"544249": "Sony",
	"5C514F": "Intel",
	"60F81D": "Apple",
	"685B35": "Apple",
	"6C2995": "Intel",
	"70106F": "Hewlett Packard",
	"74867A": "Dell",
	"8C8590": "Apple",
	"A0CEC8": "Cisco",
	"A4B197": "Apple",
	"B827EB": "Raspberry Pi",
	"BC2411": "Apple",
	"D85ED3": "Apple",
	"DC9B9C": "Apple",
	"F0D1A9": "Apple",
	"F4F5D8": "Google",
	"FCECDA": "Ubiquiti",
}

func Analyze(value string) (Analysis, error) {
	parsed, err := net.ParseMAC(strings.TrimSpace(value))
	if err != nil {
		return Analysis{}, fmt.Errorf("parse mac: %w", err)
	}
	if len(parsed) != 6 {
		return Analysis{}, fmt.Errorf("expected 48-bit mac address")
	}

	first := parsed[0]
	isMulticast := first&1 == 1
	isLocal := first&2 == 2
	normalized := strings.ToLower(parsed.String())
	oui := strings.ToUpper(strings.ReplaceAll(parsed.String()[:8], ":", ""))

	analysis := Analysis{
		Address:     normalized,
		IsPrivate:   isLocal && !isMulticast,
		IsMulticast: isMulticast,
	}
	if vendor, ok := ouiVendors[oui]; ok && !analysis.IsPrivate {
		analysis.Vendor = vendor
	}
	return analysis, nil
}
