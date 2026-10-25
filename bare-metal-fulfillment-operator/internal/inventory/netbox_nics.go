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
	"strconv"
	"strings"
)

func (c *NetBoxClient) parseNetBoxNICHostID(inventoryHostID string) (string, string, error) {
	if c == nil {
		return "", "", errors.New("NetBox inventory client is required")
	}

	namespace, name, err := ParseHostID(inventoryHostID)
	if err != nil {
		return "", "", fmt.Errorf("invalid NetBox inventory host ID: %w", err)
	}
	configuredNamespace, err := c.metal3Namespace()
	if err != nil {
		return "", "", err
	}
	if namespace != configuredNamespace {
		return "", "", fmt.Errorf("NetBox inventory host ID namespace %q does not match the configured Metal3 namespace", namespace)
	}

	const prefix = "netbox-"
	if !strings.HasPrefix(name, prefix) {
		return "", "", fmt.Errorf("NetBox inventory host name must start with %q", prefix)
	}
	deviceID := strings.TrimPrefix(name, prefix)
	numericID, err := strconv.ParseInt(deviceID, 10, 32)
	if err != nil || numericID <= 0 || strconv.FormatInt(numericID, 10) != deviceID {
		return "", "", fmt.Errorf("NetBox inventory host name must contain a canonical positive device ID")
	}

	return name, deviceID, nil
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
