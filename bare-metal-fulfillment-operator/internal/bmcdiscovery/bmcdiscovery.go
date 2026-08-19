/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package bmcdiscovery discovers BMC addresses for bare-metal hosts.
// It classifies BMC protocols from interface names, discovers Redfish
// system paths via MAC-address matching, and constructs validated BMC
// URLs suitable for Metal3 BareMetalHost spec.bmc.address.
package bmcdiscovery

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
)

var (
	ErrNoBMCInterface     = errors.New("no matching BMC interface found in device interfaces")
	ErrUnsupportedBMCType = errors.New("unsupported BMC protocol type")
	ErrNoMACMatch         = errors.New("no Redfish system found matching boot MAC address")
	ErrInvalidBMCTarget   = errors.New("invalid BMC target")
)

// Protocol represents a BMC protocol type classified from a device
// interface name.
type Protocol string

const (
	ProtocolRedfish Protocol = "redfish"
	ProtocolIPMI    Protocol = "ipmi"
	ProtocolILO     Protocol = "ilo"
	ProtocolDRAC    Protocol = "drac"
)

// DeviceInterface represents a network interface entry from a device's
// interface list. Only the fields needed for BMC discovery are included.
type DeviceInterface struct {
	// ChildType is the interface type identifier used to distinguish
	// BMC interfaces from other interface types (e.g. data network).
	ChildType string
	// Name encodes the BMC protocol (e.g. "rf0" for Redfish, "ipmi0"
	// for IPMI, "ilo0" for iLO, "drac0" for iDRAC).
	Name string
	// IP is the BMC management interface IP address.
	IP string
}

// BMCInfo holds the BMC connection information needed for address
// construction and Redfish discovery.
type BMCInfo struct {
	IP       string
	Protocol Protocol
}

var bmcTypePatterns = map[Protocol]*regexp.Regexp{
	ProtocolRedfish: regexp.MustCompile(`^rf\d+$`),
	ProtocolIPMI:    regexp.MustCompile(`^ipmi\d+$`),
	ProtocolILO:     regexp.MustCompile(`^ilo\d+$`),
	ProtocolDRAC:    regexp.MustCompile(`^drac\d+$`),
}

var redfishCompatiblePrefixes = map[Protocol]string{
	ProtocolRedfish: "redfish-virtualmedia",
	ProtocolDRAC:    "idrac-virtualmedia",
	ProtocolILO:     "ilo5-virtualmedia",
}

func classifyProtocol(interfaceName string) (Protocol, error) {
	name := strings.ToLower(interfaceName)
	for protocol, pattern := range bmcTypePatterns {
		if pattern.MatchString(name) {
			return protocol, nil
		}
	}
	return "", fmt.Errorf("%w: %q", ErrUnsupportedBMCType, interfaceName)
}

func isRedfishCompatible(p Protocol) bool {
	_, ok := redfishCompatiblePrefixes[p]
	return ok
}

// ExtractBMCInfo scans a device's interfaces for the first entry whose
// ChildType matches childType, then classifies the BMC protocol from
// the interface name.
func ExtractBMCInfo(interfaces []DeviceInterface, childType string) (*BMCInfo, error) {
	for _, iface := range interfaces {
		if iface.ChildType != childType {
			continue
		}
		protocol, err := classifyProtocol(iface.Name)
		if err != nil {
			return nil, err
		}
		return &BMCInfo{
			IP:       iface.IP,
			Protocol: protocol,
		}, nil
	}
	return nil, ErrNoBMCInterface
}

func formatHost(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed != nil && parsed.To4() == nil {
		return "[" + ip + "]"
	}
	return ip
}

func buildStaticAddress(bmcIP string) string {
	return fmt.Sprintf("ipmi://%s", formatHost(bmcIP))
}

func buildRedfishAddress(bmcIP string, protocol Protocol, systemPath string) string {
	prefix := redfishCompatiblePrefixes[protocol]
	return fmt.Sprintf("%s+https://%s%s", prefix, formatHost(bmcIP), systemPath)
}

// Resolve constructs a validated BMC address from the given BMCInfo.
// For IPMI, it returns a static URL. For Redfish-compatible protocols
// (Redfish, iLO, iDRAC), it uses the provided Discoverer to find the
// system path via MAC-address matching.
//
// Callers that have raw device interface data can use ExtractBMCInfo
// to build the BMCInfo first.
func Resolve(
	ctx context.Context,
	info *BMCInfo,
	bootMAC string,
	username string,
	password string,
	discoverer Discoverer,
) (string, error) {
	if !isRedfishCompatible(info.Protocol) {
		address := buildStaticAddress(info.IP)
		if err := ValidateBMCAddress(address); err != nil {
			return "", err
		}
		return address, nil
	}

	if discoverer == nil {
		return "", fmt.Errorf("discoverer is required for %s protocol", info.Protocol)
	}

	systemPath, err := discoverer.DiscoverSystemPath(ctx, info.IP, bootMAC, username, password)
	if err != nil {
		return "", fmt.Errorf("redfish discovery failed for %s: %w", info.IP, err)
	}

	address := buildRedfishAddress(info.IP, info.Protocol, systemPath)
	if err := ValidateBMCAddress(address); err != nil {
		return "", err
	}

	return address, nil
}
