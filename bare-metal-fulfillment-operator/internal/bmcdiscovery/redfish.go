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

package bmcdiscovery

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/stmcginnis/gofish"
)

// Discoverer discovers Redfish system paths by querying a BMC's
// Redfish API and matching ethernet interface MAC addresses to the
// host's boot MAC address.
type Discoverer interface {
	DiscoverSystemPath(ctx context.Context, bmcIP, bootMAC, username, password string) (string, error)
}

var _ Discoverer = (*GofishDiscoverer)(nil)

// GofishDiscoverer implements Discoverer using the gofish Redfish
// client library. Set InsecureSkipVerify to true only for
// development or when BMCs use self-signed certificates.
type GofishDiscoverer struct {
	InsecureSkipVerify bool
}

// DiscoverSystemPath connects to the BMC at bmcIP, iterates over
// Redfish Systems and their EthernetInterfaces, and returns the
// system's OData ID path that has an interface matching bootMAC.
func (d *GofishDiscoverer) DiscoverSystemPath(
	ctx context.Context,
	bmcIP, bootMAC, username, password string,
) (string, error) {
	config := gofish.ClientConfig{
		Endpoint: "https://" + formatHost(bmcIP),
		Username: username,
		Password: password,
		Insecure: d.InsecureSkipVerify,
	}

	client, err := gofish.ConnectContext(ctx, config)
	if err != nil {
		return "", fmt.Errorf("failed to connect to Redfish at %s: %w", bmcIP, err)
	}
	defer client.Logout()

	service := client.GetService()
	systems, err := service.Systems()
	if err != nil {
		return "", fmt.Errorf("failed to list Redfish systems on %s: %w", bmcIP, err)
	}

	var queryErrors []error
	for _, system := range systems {
		ethInterfaces, err := system.EthernetInterfaces()
		if err != nil {
			queryErrors = append(queryErrors, fmt.Errorf("system %s: %w", system.ODataID, err))
			continue
		}

		for _, eth := range ethInterfaces {
			if strings.EqualFold(eth.MACAddress, bootMAC) {
				return system.ODataID, nil
			}
		}
	}

	if len(queryErrors) > 0 {
		return "", fmt.Errorf("%w: boot MAC %s not found on BMC %s (query errors: %w)",
			ErrNoMACMatch, bootMAC, bmcIP, errors.Join(queryErrors...))
	}

	return "", fmt.Errorf("%w: boot MAC %s not found on BMC %s", ErrNoMACMatch, bootMAC, bmcIP)
}
