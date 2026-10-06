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

const netBoxHostNamePrefix = "netbox-"

var errNetBoxClientNotImplemented = errors.New("NetBox inventory client is not implemented")

// NetBoxClient is the scaffold for the NetBox-backed inventory implementation.
// Its inventory operations return an error until the secure API adapter is implemented.
type NetBoxClient struct{}

var (
	_ Client        = (*NetBoxClient)(nil)
	_ NewClientFunc = NewNetBoxClient
)

// NewNetBoxClient constructs the NetBox inventory client scaffold.
func NewNetBoxClient(_ context.Context, _ *Config) (Client, error) {
	return &NetBoxClient{}, nil
}

func (*NetBoxClient) FindFreeHost(_ context.Context, _ map[string]string) (*Host, error) {
	return nil, errNetBoxClientNotImplemented
}

func (*NetBoxClient) AssignHost(_ context.Context, _ string, _ string, _ map[string]string) (*Host, error) {
	return nil, errNetBoxClientNotImplemented
}

func (*NetBoxClient) UnassignHost(_ context.Context, _ string, _ []string) error {
	return errNetBoxClientNotImplemented
}

func (*NetBoxClient) GetHostNICs(_ context.Context, _ string) ([]HostNIC, error) {
	return nil, errNetBoxClientNotImplemented
}

type netBoxHostIdentity struct {
	namespace       string
	deviceID        int64
	name            string
	inventoryHostID string
}

func newNetBoxHostIdentity(namespace string, deviceID int64) (netBoxHostIdentity, error) {
	if namespace == "" || strings.Contains(namespace, "/") {
		return netBoxHostIdentity{}, fmt.Errorf("invalid Metal3 namespace for NetBox host identity")
	}

	name := netBoxHostNamePrefix + strconv.FormatInt(deviceID, 10)
	return netBoxHostIdentity{
		namespace:       namespace,
		deviceID:        deviceID,
		name:            name,
		inventoryHostID: namespace + "/" + name,
	}, nil
}

func parseNetBoxHostIdentity(inventoryHostID, configuredNamespace string) (netBoxHostIdentity, error) {
	namespace, name, found := strings.Cut(inventoryHostID, "/")
	if !found || namespace == "" || namespace != configuredNamespace || !strings.HasPrefix(name, netBoxHostNamePrefix) {
		return netBoxHostIdentity{}, fmt.Errorf("invalid persisted NetBox host identity")
	}

	deviceID, err := parseNetBoxDeviceID(name[len(netBoxHostNamePrefix):])
	if err != nil {
		return netBoxHostIdentity{}, fmt.Errorf("invalid persisted NetBox host identity")
	}

	return netBoxHostIdentity{
		namespace:       namespace,
		deviceID:        deviceID,
		name:            name,
		inventoryHostID: inventoryHostID,
	}, nil
}

func parseNetBoxDeviceID(rawID string) (int64, error) {
	id, err := strconv.ParseInt(rawID, 10, 64)
	if err != nil || strconv.FormatInt(id, 10) != rawID {
		return 0, fmt.Errorf("invalid NetBox device ID: expected a canonical decimal int64")
	}
	return id, nil
}
