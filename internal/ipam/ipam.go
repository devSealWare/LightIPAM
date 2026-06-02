package ipam

import (
	"fmt"
	"math/big"
	"net/netip"
)

func NormalizeCIDR(value string) (string, error) {
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return "", fmt.Errorf("parse cidr: %w", err)
	}
	if !prefix.Addr().Is4() {
		return "", fmt.Errorf("only IPv4 subnets are supported")
	}
	prefix = prefix.Masked()
	return prefix.String(), nil
}

func NormalizeIPv4(value string) (string, error) {
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return "", fmt.Errorf("parse address: %w", err)
	}
	if !addr.Is4() {
		return "", fmt.Errorf("only IPv4 addresses are supported")
	}
	return addr.String(), nil
}

func AddressCapacity(cidr string) (uint64, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return 0, err
	}
	if !prefix.Addr().Is4() {
		return 0, fmt.Errorf("only IPv4 subnets are supported")
	}
	bits := 32 - prefix.Bits()
	if bits < 0 {
		return 0, fmt.Errorf("invalid prefix")
	}
	return uint64(1) << bits, nil
}

func Contains(cidr, address string) (bool, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return false, err
	}
	addr, err := netip.ParseAddr(address)
	if err != nil {
		return false, err
	}
	return prefix.Contains(addr), nil
}

func UtilizationPercent(touched, capacity uint64) float64 {
	if capacity == 0 {
		return 0
	}
	percent := new(big.Rat).SetFrac(new(big.Int).SetUint64(touched*10000), new(big.Int).SetUint64(capacity))
	value, _ := percent.Float64()
	return value / 100
}
