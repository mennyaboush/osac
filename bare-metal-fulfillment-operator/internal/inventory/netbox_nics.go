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

package inventory

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/osac-project/osac/bare-metal-fulfillment-operator/internal/netboxclient"
)

func (c *NetBoxClient) parseNetBoxNICHostID(inventoryHostID string) (string, string, error) {
	if c == nil {
		return "", "", errors.New("NetBox inventory client is required")
	}

	_, deviceID, err := c.parseNetBoxHostID(inventoryHostID)
	if err != nil {
		return "", "", err
	}
	numericID, err := strconv.ParseInt(deviceID, 10, 32)
	if err != nil || numericID <= 0 || strconv.FormatInt(numericID, 10) != deviceID {
		return "", "", fmt.Errorf("NetBox inventory host name must contain a canonical positive device ID")
	}

	return netBoxHostPrefix + deviceID, deviceID, nil
}

func (c *NetBoxClient) GetHostNICs(ctx context.Context, inventoryHostID string) ([]HostNIC, error) {
	bmhName, _, err := c.parseNetBoxNICHostID(inventoryHostID)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	macs, err := c.bmhManager.GetHardwareNICs(ctx, bmhName)
	if err != nil {
		return nil, fmt.Errorf("failed to read inspected NICs for NetBox host %q: %w", bmhName, err)
	}

	return hostNICsFromMACs(macs), nil
}

func hostNICsFromMACs(macs []string) []HostNIC {
	var nics []HostNIC
	for _, mac := range macs {
		if mac == "" {
			continue
		}
		nics = append(nics, HostNIC{MAC: strings.ToLower(mac)})
	}
	return nics
}

// GetHostLogicalPortMACs resolves logical port names from native NetBox interfaces.
func (c *NetBoxClient) GetHostLogicalPortMACs(ctx context.Context, inventoryHostID string) (map[string]string, error) {
	_, deviceID, err := c.parseNetBoxNICHostID(inventoryHostID)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("NetBox logical MAC lookup cancelled: %w", err)
	}
	if c.api == nil {
		return nil, errors.New("NetBox API is required for logical MAC lookup")
	}

	result := make(map[string]string)
	seen := make(map[string]string)
	err = c.api.ForEachDeviceInterface(ctx, deviceID, func(iface netboxclient.DeviceInterface) (bool, error) {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		if err := addNetBoxLogicalPortMAC(result, seen, iface); err != nil {
			return false, err
		}
		return true, nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to resolve logical MACs from NetBox: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("NetBox logical MAC lookup cancelled: %w", err)
	}

	return result, nil
}

func netBoxLogicalPortName(iface netboxclient.DeviceInterface) (string, error) {
	if rawAlias, exists := iface.CustomFields["osac_logical_port"]; exists && rawAlias != nil {
		alias, ok := rawAlias.(string)
		if !ok {
			return "", fmt.Errorf("NetBox interface %q has a non-text osac_logical_port alias", iface.ID)
		}
		if alias != "" {
			if strings.TrimSpace(alias) != alias {
				return "", fmt.Errorf("NetBox interface %q has whitespace around osac_logical_port", iface.ID)
			}
			return alias, nil
		}
	}

	if iface.Name == "" || strings.TrimSpace(iface.Name) != iface.Name {
		return "", fmt.Errorf("NetBox interface %q has an invalid native name", iface.ID)
	}
	return iface.Name, nil
}

func normalizeNetBoxInterfaceMAC(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	mac, err := net.ParseMAC(raw)
	if err != nil || len(mac) != 6 {
		return "", errors.New("invalid 48-bit MAC address")
	}
	return mac.String(), nil
}

func addNetBoxLogicalPortMAC(result map[string]string, seen map[string]string, iface netboxclient.DeviceInterface) error {
	logicalName, err := netBoxLogicalPortName(iface)
	if err != nil {
		return err
	}
	if previousID, exists := seen[logicalName]; exists {
		return fmt.Errorf("NetBox interfaces %q and %q resolve to the same logical port", previousID, iface.ID)
	}
	seen[logicalName] = iface.ID

	mac, err := normalizeNetBoxInterfaceMAC(iface.PrimaryMAC)
	if err != nil {
		return fmt.Errorf("NetBox interface %q has an invalid primary MAC: %w", iface.ID, err)
	}
	if mac == "" {
		return nil
	}
	result[logicalName] = mac
	return nil
}
