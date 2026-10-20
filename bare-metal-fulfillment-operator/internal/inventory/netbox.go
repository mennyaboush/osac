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
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/osac-project/osac/bare-metal-fulfillment-operator/internal/baremetalhost"
	"github.com/osac-project/osac/bare-metal-fulfillment-operator/internal/netboxclient"
	"github.com/osac-project/osac/bare-metal-fulfillment-operator/internal/shared"
)

const (
	netBoxHostPrefix   = "netbox-"
	netBoxStatusActive = "active"
	netBoxStatusStaged = "staged"
)

var errNetBoxClientNotImplemented = errors.New("NetBox inventory client is not implemented")

// NetBoxAPI defines the operations needed by the inventory adapter. It is
// satisfied by netboxclient.Client and keeps generated SDK calls behind a
// consumer-side interface.
type NetBoxAPI interface {
	ForEachDevice(ctx context.Context, query netboxclient.DeviceQuery, visit func(netboxclient.Device) (bool, error)) error
	ForEachDeviceCustomField(ctx context.Context, visit func(netboxclient.CustomField) (bool, error)) error
	GetDevice(ctx context.Context, id string) (netboxclient.DeviceSnapshot, error)
	PatchDevice(ctx context.Context, id string, patch netboxclient.DevicePatch, etag string) (netboxclient.DeviceSnapshot, error)
}

// NetBoxClientConfig contains the mounted-file and endpoint settings for NetBox.
type NetBoxClientConfig struct {
	URL               string `json:"url"`
	TokenFile         string `json:"tokenFile"`
	CAFile            string `json:"caFile"`
	AllowInsecureHTTP bool   `json:"allowInsecureHTTP"`
}

// ParseNetBoxOptions extracts the NetBox-specific settings from inventory
// configuration. The token value itself must remain in the mounted file.
func ParseNetBoxOptions(options map[string]any) (*NetBoxClientConfig, error) {
	netBoxOptions, ok := options["netbox"]
	if !ok {
		return nil, fmt.Errorf("netbox options not found in config")
	}

	raw, err := json.Marshal(netBoxOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to parse netbox options")
	}

	var config NetBoxClientConfig
	if err := json.Unmarshal(raw, &config); err != nil {
		return nil, fmt.Errorf("failed to parse netbox options")
	}
	if config.URL == "" {
		return nil, fmt.Errorf("netbox url is required in config")
	}
	if config.TokenFile == "" {
		return nil, fmt.Errorf("netbox tokenFile is required in config")
	}
	return &config, nil
}

// NetBoxClient implements inventory.Client against NetBox's device API.
type NetBoxClient struct {
	api        NetBoxAPI
	bmhManager baremetalhost.BMHLifecycleManager
	hostClass  string
}

var (
	_ Client = (*NetBoxClient)(nil)
)

// NewNetBoxAPI constructs the secure NetBox API dependency from mounted configuration.
func NewNetBoxAPI(config *Config) (NetBoxAPI, error) {
	if config == nil {
		return nil, fmt.Errorf("netbox inventory config is required")
	}
	netBoxConfig, err := ParseNetBoxOptions(config.Options)
	if err != nil {
		return nil, err
	}

	api, err := netboxclient.New(netboxclient.Config{
		Endpoint:          netBoxConfig.URL,
		TokenFile:         netBoxConfig.TokenFile,
		CAFile:            netBoxConfig.CAFile,
		AllowInsecureHTTP: netBoxConfig.AllowInsecureHTTP,
	})
	if err != nil {
		return nil, err
	}
	return api, nil
}

// NewNetBoxClient creates a NetBox inventory client with injected dependencies.
func NewNetBoxClient(api NetBoxAPI, bmhManager baremetalhost.BMHLifecycleManager, hostClass string) *NetBoxClient {
	return &NetBoxClient{
		api:        api,
		bmhManager: bmhManager,
		hostClass:  hostClass,
	}
}

func (c *NetBoxClient) FindFreeHost(ctx context.Context, selector map[string]string) (*Host, error) {
	return c.findFreeHost(ctx, buildFreeHostQuery(selector))
}

func (c *NetBoxClient) findFreeHost(ctx context.Context, query netboxclient.DeviceQuery) (*Host, error) {
	namespace, err := c.metal3Namespace()
	if err != nil {
		return nil, err
	}

	var foundHost *Host
	err = c.api.ForEachDevice(ctx, query, func(device netboxclient.Device) (bool, error) {
		foundHost = c.netBoxHostFromDevice(namespace, device)
		return false, nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to search NetBox for a free host: %w", err)
	}
	return foundHost, nil
}

func (c *NetBoxClient) metal3Namespace() (string, error) {
	if c.bmhManager != nil {
		if namespace := c.bmhManager.Namespace(); namespace != "" {
			return namespace, nil
		}
	}
	return "", errors.New("NetBox inventory requires a Metal3 namespace")
}

func (c *NetBoxClient) netBoxHostFromDevice(namespace string, device netboxclient.Device) *Host {
	name := netBoxHostPrefix + device.ID
	return &Host{
		InventoryHostID: fmt.Sprintf("%s/%s", namespace, name),
		Name:            name,
		HostClass:       c.hostClass,
		ProvisionState:  shared.OsacDefaultProvisionStateValue,
		ManagedBy:       shared.OsacDefaultManagedByValue,
		Ready:           true,
	}
}

func buildFreeHostQuery(selector map[string]string) netboxclient.DeviceQuery {
	query := make(netboxclient.DeviceQuery, len(selector)+3)
	for key, value := range selector {
		query["cf_"+key] = value
	}
	query["status"] = netBoxStatusStaged
	query["cf_osac_managed"] = "true"
	query["cf_osac_instance_id__empty"] = "true"
	return query
}

func (c *NetBoxClient) AssignHost(ctx context.Context, inventoryHostID string, bareMetalInstanceID string, _ map[string]string) (*Host, error) {
	if bareMetalInstanceID == "" {
		return nil, errors.New("invalid input: bareMetalInstanceID is empty")
	}
	namespace, deviceID, err := c.parseNetBoxHostID(inventoryHostID)
	if err != nil {
		return nil, err
	}
	snapshot, err := c.readNetBoxDevice(ctx, deviceID)
	if err != nil {
		return nil, err
	}
	return c.assignNetBoxDevice(ctx, namespace, deviceID, bareMetalInstanceID, snapshot)
}

func (c *NetBoxClient) parseNetBoxHostID(inventoryHostID string) (string, string, error) {
	namespace, name, err := ParseHostID(inventoryHostID)
	if err != nil {
		return "", "", errors.New("invalid NetBox inventory host ID: expected namespace/name format")
	}
	if !strings.HasPrefix(name, netBoxHostPrefix) {
		return "", "", errors.New("invalid NetBox inventory host ID")
	}
	deviceID := strings.TrimPrefix(name, netBoxHostPrefix)
	if deviceID == "" {
		return "", "", errors.New("invalid NetBox inventory host ID")
	}
	if c.bmhManager == nil || c.bmhManager.Namespace() == "" {
		return "", "", errors.New("NetBox inventory requires a Metal3 namespace")
	}
	if namespace != c.bmhManager.Namespace() {
		return "", "", errors.New("NetBox inventory host ID is outside the Metal3 namespace")
	}
	return namespace, deviceID, nil
}

func (c *NetBoxClient) readNetBoxDevice(ctx context.Context, deviceID string) (netboxclient.DeviceSnapshot, error) {
	if c.api == nil {
		return netboxclient.DeviceSnapshot{}, errNetBoxClientNotImplemented
	}
	snapshot, err := c.api.GetDevice(ctx, deviceID)
	if err != nil {
		return netboxclient.DeviceSnapshot{}, fmt.Errorf("failed to read NetBox device: %w", err)
	}
	if snapshot.Device.ID != deviceID {
		return netboxclient.DeviceSnapshot{}, errors.New("NetBox returned a different device than requested")
	}
	return snapshot, nil
}

func (c *NetBoxClient) assignNetBoxDevice(ctx context.Context, namespace, deviceID, bareMetalInstanceID string, snapshot netboxclient.DeviceSnapshot) (*Host, error) {
	host, claimable, err := c.netBoxAssignmentForDevice(namespace, snapshot.Device, bareMetalInstanceID)
	if err != nil {
		return nil, err
	}
	if host != nil || !claimable {
		return host, nil
	}
	if strings.TrimSpace(snapshot.ETag) == "" {
		return nil, errors.New("NetBox device response is missing an ETag")
	}
	return c.claimNetBoxDevice(ctx, namespace, deviceID, bareMetalInstanceID, snapshot.ETag)
}

func (c *NetBoxClient) claimNetBoxDevice(ctx context.Context, namespace, deviceID, bareMetalInstanceID, etag string) (*Host, error) {
	active := netBoxStatusActive
	claimed, err := c.api.PatchDevice(ctx, deviceID, netboxclient.DevicePatch{
		Status:       &active,
		CustomFields: map[string]interface{}{"osac_instance_id": bareMetalInstanceID},
	}, etag)
	if err != nil {
		var apiErr *netboxclient.APIError
		if !errors.As(err, &apiErr) || apiErr.Kind != netboxclient.ErrorKindConflict {
			return nil, fmt.Errorf("failed to claim NetBox device: %w", err)
		}
		return c.reconcileNetBoxClaimConflict(ctx, namespace, deviceID, bareMetalInstanceID)
	}
	if claimed.Device.ID != deviceID {
		return nil, errors.New("NetBox returned a different device after the claim")
	}
	host, _, err := c.netBoxAssignmentForDevice(namespace, claimed.Device, bareMetalInstanceID)
	if err != nil {
		return nil, err
	}
	if host == nil {
		return nil, errors.New("NetBox response did not confirm the host assignment")
	}
	return host, nil
}

func (c *NetBoxClient) reconcileNetBoxClaimConflict(ctx context.Context, namespace, deviceID, bareMetalInstanceID string) (*Host, error) {
	latest, err := c.readNetBoxDevice(ctx, deviceID)
	if err != nil {
		return nil, fmt.Errorf("failed to re-read NetBox device after a claim conflict: %w", err)
	}
	host, claimable, err := c.netBoxAssignmentForDevice(namespace, latest.Device, bareMetalInstanceID)
	if err != nil {
		return nil, err
	}
	if host != nil || !claimable {
		return host, nil
	}
	// Preserve the saved ID when the device is still free; the next reconcile
	// will use a fresh ETag rather than selecting a different device.
	return nil, errors.New("NetBox device changed during assignment; retry on the next reconciliation")
}

func (c *NetBoxClient) netBoxAssignmentForDevice(namespace string, device netboxclient.Device, bareMetalInstanceID string) (*Host, bool, error) {
	owner, claimable, err := netBoxDeviceAssignmentState(device)
	if err != nil {
		return nil, false, err
	}
	if claimable || owner != bareMetalInstanceID {
		return nil, claimable, nil
	}
	host := c.netBoxHostFromDevice(namespace, device)
	host.BareMetalInstanceID = owner
	return host, false, nil
}

func netBoxDeviceAssignmentState(device netboxclient.Device) (string, bool, error) {
	owner, err := netBoxInstanceOwner(device)
	if err != nil {
		return "", false, err
	}
	if device.Status == "" {
		return "", false, errors.New("NetBox device has no status")
	}
	if owner == "" {
		if device.Status == netBoxStatusActive {
			return "", false, errors.New("NetBox device is active without an assigned instance")
		}
		return owner, device.Status == netBoxStatusStaged, nil
	}
	if device.Status != netBoxStatusActive {
		return "", false, errors.New("NetBox device has an assigned instance but is not active")
	}
	return owner, false, nil
}

func netBoxInstanceOwner(device netboxclient.Device) (string, error) {
	value, ok := device.CustomFields["osac_instance_id"]
	if !ok || value == nil {
		return "", nil
	}
	owner, ok := value.(string)
	if !ok || strings.TrimSpace(owner) != owner {
		return "", errors.New("NetBox device has a malformed osac_instance_id custom field")
	}
	return owner, nil
}

func (*NetBoxClient) UnassignHost(_ context.Context, _ string, _ []string) error {
	return errNetBoxClientNotImplemented
}

func (*NetBoxClient) GetHostNICs(_ context.Context, _ string) ([]HostNIC, error) {
	return nil, errNetBoxClientNotImplemented
}

// GetHostLogicalPortMACs is not implemented until NetBox inventory operations are added.
func (*NetBoxClient) GetHostLogicalPortMACs(_ context.Context, _ string) (map[string]string, error) {
	return nil, errNetBoxClientNotImplemented
}
