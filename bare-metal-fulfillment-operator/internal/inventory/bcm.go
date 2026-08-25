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
	"fmt"
	"math/rand"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/certwatcher"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/osac-project/osac/bare-metal-fulfillment-operator/internal/baremetalhost"
	"github.com/osac-project/osac/bare-metal-fulfillment-operator/internal/bcmclient"
	"github.com/osac-project/osac/bare-metal-fulfillment-operator/internal/bmcdiscovery"
	"github.com/osac-project/osac/bare-metal-fulfillment-operator/internal/shared"
)

const certBaseDir = "/etc/osac/certs"

// BCMAPI defines the BCM client operations needed by the inventory adapter.
// Satisfied by *bcmclient.Client; defined here so tests can substitute a mock
// without depending on the bcmclient package.
//
//go:generate mockgen -destination=bcm_mock_test.go -package=inventory . BCMAPI,BMHLifecycleManager,BMCDiscoverer
type BCMAPI interface {
	CertWatcher() *certwatcher.CertWatcher
	GetDevices(ctx context.Context) ([]bcmclient.Device, error)
	GetDevice(ctx context.Context, hostname string) (*bcmclient.Device, error)
	UpdateDevice(ctx context.Context, deviceRaw json.RawMessage) (*bcmclient.UpdateResponse, error)
}

// BMHLifecycleManager abstracts BareMetalHost CR operations for testability.
// Satisfied by *baremetalhost.Manager.
type BMHLifecycleManager interface {
	CreateBMH(ctx context.Context, params baremetalhost.CreateParams) error
	BMHExists(ctx context.Context, name string) (bool, error)
	IsBMHReady(ctx context.Context, name string) (bool, error)
	ReadBMCCredentials(ctx context.Context, secretName string) (username, password string, err error)
	GetHardwareNICs(ctx context.Context, name string) ([]string, error)
	Namespace() string
}

// BMCDiscoverer resolves BMC system paths via Redfish. Satisfied by
// *bmcdiscovery.GofishDiscoverer; defined here so tests can substitute
// a mock without making real Redfish connections.
type BMCDiscoverer interface {
	DiscoverSystemPath(ctx context.Context, bmcIP, bootMAC, username, password string) (string, error)
}

const bmcInterfaceChildType = "NetworkBmcInterface"

var (
	_ Client = (*BCMClient)(nil)

	macPattern      = regexp.MustCompile(`^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$`)
	hostnamePattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9\-]*[a-z0-9])?$`)

	bcmHostsAvailable = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "osac_bcm_hosts_available",
			Help: "Number of unassigned BCM LiteNodes by host type",
		},
		[]string{"host_type"},
	)
)

func init() {
	metrics.Registry.MustRegister(bcmHostsAvailable)
}

// BCMClientConfig holds the BCM-specific options parsed from the inventory config.
type BCMClientConfig struct {
	URL                string `json:"url"`
	CredentialsSecret  string `json:"credentialsSecret"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

// ParseBCMOptions extracts and validates BCM options from the inventory config.
func ParseBCMOptions(options map[string]any) (*BCMClientConfig, error) {
	bcmOpts, ok := options["bcm"]
	if !ok {
		return nil, fmt.Errorf("bcm options not found in config")
	}

	raw, err := json.Marshal(bcmOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal bcm options: %w", err)
	}

	var cfg BCMClientConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal bcm options: %w", err)
	}

	if cfg.URL == "" {
		return nil, fmt.Errorf("bcm url is required in config")
	}
	if cfg.CredentialsSecret == "" {
		return nil, fmt.Errorf("bcm credentialsSecret is required in config")
	}

	certDir := filepath.Join(certBaseDir, cfg.CredentialsSecret)
	if !strings.HasPrefix(certDir, certBaseDir+"/") {
		return nil, fmt.Errorf("bcm credentialsSecret resolves outside cert directory")
	}

	return &cfg, nil
}

// BCMClient implements inventory.Client by wrapping a BCMAPI
// for BCM API communication and a BMHLifecycleManager for BMH lifecycle.
type BCMClient struct {
	client        BCMAPI
	bmhManager    BMHLifecycleManager
	bmcDiscoverer BMCDiscoverer
	hostClass     string
}

// NewBCMClient creates a BCM inventory client with injected dependencies.
func NewBCMClient(client BCMAPI, bmhManager BMHLifecycleManager, hostClass string) *BCMClient {
	return &BCMClient{
		client:     client,
		bmhManager: bmhManager,
		hostClass:  hostClass,
	}
}

// SetBMCDiscoverer sets the Redfish discoverer used for Priority 2 BMC
// address resolution. When nil, Redfish-compatible protocols return an
// error; only IPMI (static URL) works without a discoverer.
func (c *BCMClient) SetBMCDiscoverer(d BMCDiscoverer) {
	c.bmcDiscoverer = d
}

// CertWatcher returns the certificate watcher for registration with the
// controller manager. The manager calls Start on it to enable automatic
// certificate rotation.
func (c *BCMClient) CertWatcher() *certwatcher.CertWatcher {
	return c.client.CertWatcher()
}

// FindFreeHost queries BCM for all devices and returns a randomly selected
// free LiteNode matching the requested hostType. All filtering is client-side
// because the BCM JSON API has no server-side filtering.
func (c *BCMClient) FindFreeHost(ctx context.Context, matchExpressions map[string]string) (*Host, error) {
	log := ctrllog.FromContext(ctx)
	log.Info("Finding free BCM host")

	matchManagedBy := matchExpressions["managedBy"]
	if matchManagedBy == "" {
		matchManagedBy = shared.OsacDefaultManagedByValue
	}
	if matchManagedBy != shared.OsacDefaultManagedByValue {
		return nil, nil
	}

	devices, err := c.client.GetDevices(ctx)
	if err != nil {
		return nil, fmt.Errorf("FindFreeHost: %w", err)
	}

	hostType := matchExpressions["hostType"]

	candidates := make([]bcmclient.Device, 0, len(devices))
	for _, d := range devices {
		if d.ChildType != "LiteNode" {
			continue
		}

		if d.ExtraValues == nil {
			continue
		}

		resourceClass, _ := d.ExtraValues[bcmclient.ExtraValueResourceClass].(string)
		if resourceClass == "" {
			continue
		}

		if hostType != "" && resourceClass != hostType {
			continue
		}

		if _, assigned := d.ExtraValues[bcmclient.ExtraValueInstanceID]; assigned {
			continue
		}

		if !hostnamePattern.MatchString(d.Hostname) || len(d.Hostname) > 63 {
			continue
		}

		if !macPattern.MatchString(d.MAC) || d.MAC == "00:00:00:00:00:00" {
			continue
		}

		candidates = append(candidates, d)
	}

	bcmHostsAvailable.Reset()
	availableByType := map[string]float64{}
	for _, cd := range candidates {
		rc, _ := cd.ExtraValues[bcmclient.ExtraValueResourceClass].(string)
		availableByType[rc]++
	}
	for t, count := range availableByType {
		bcmHostsAvailable.WithLabelValues(t).Set(count)
	}

	if len(candidates) == 0 {
		return nil, nil
	}

	rand.Shuffle(len(candidates), func(i, j int) {
		candidates[i], candidates[j] = candidates[j], candidates[i]
	})

	selected := &candidates[0]
	resourceClass, _ := selected.ExtraValues[bcmclient.ExtraValueResourceClass].(string)

	return &Host{
		InventoryHostID: fmt.Sprintf("%s/%s", c.bmhManager.Namespace(), selected.Hostname),
		Name:            selected.Hostname,
		HostType:        resourceClass,
		HostClass:       c.hostClass,
		ManagedBy:       shared.OsacDefaultManagedByValue,
	}, nil
}

// AssignHost records the assignment identifier in BCM, resolves the BMC
// address, and creates a BareMetalHost CR for Metal3 power management.
// Uses full-object replacement because BCM's updateDevice rejects partial
// objects. Only osac_instance_id is written — no tenant-identifying data.
func (c *BCMClient) AssignHost(ctx context.Context, inventoryHostID string, bareMetalInstanceID string, _ map[string]string) (*Host, error) {
	log := ctrllog.FromContext(ctx)

	if bareMetalInstanceID == "" {
		return nil, fmt.Errorf("invalid input: bareMetalInstanceID is empty")
	}

	_, hostname, err := ParseHostID(inventoryHostID)
	if err != nil {
		return nil, err
	}

	log.Info("Assigning BCM host", "hostname", hostname, "bareMetalInstanceID", bareMetalInstanceID)

	device, err := c.client.GetDevice(ctx, hostname)
	if err != nil {
		return nil, fmt.Errorf("failed to get BCM device %s: %w", hostname, err)
	}

	if device == nil {
		return c.handleDeviceNotFound(ctx, hostname)
	}

	if device.ExtraValues != nil {
		if existingID, ok := device.ExtraValues[bcmclient.ExtraValueInstanceID]; ok {
			existingIDStr, _ := existingID.(string)
			if existingIDStr == bareMetalInstanceID {
				log.Info("BCM host already assigned to this instance, skipping write", "hostname", hostname)
				return c.ensureBMHAndCheckReadiness(ctx, device, bareMetalInstanceID)
			}
			log.Info("BCM host assigned to another instance", "hostname", hostname, "existingInstanceID", existingIDStr)
			return nil, nil
		}
	}

	verifiedDevice, err := c.writeAndVerifyAssignment(ctx, device, hostname, bareMetalInstanceID)
	if err != nil {
		return nil, err
	}
	if verifiedDevice == nil {
		return nil, nil
	}

	log.Info("BCM host assigned successfully", "hostname", hostname)
	return c.ensureBMHAndCheckReadiness(ctx, verifiedDevice, bareMetalInstanceID)
}

func (c *BCMClient) handleDeviceNotFound(ctx context.Context, hostname string) (*Host, error) {
	log := ctrllog.FromContext(ctx)

	exists, err := c.bmhManager.BMHExists(ctx, hostname)
	if err != nil {
		return nil, err
	}
	if !exists {
		log.Info("BCM device not found and no BMH exists, clearing for retry", "hostname", hostname)
		return nil, nil
	}

	return nil, fmt.Errorf(
		"BCM device %q no longer exists in BCM inventory but BareMetalHost CR exists"+
			" — delete the BareMetalInstance or re-register the device in BCM", hostname)
}

func (c *BCMClient) writeAndVerifyAssignment(ctx context.Context, device *bcmclient.Device, hostname, bareMetalInstanceID string) (*bcmclient.Device, error) {
	raw, err := bcmclient.SetExtraValue(device.Raw, bcmclient.ExtraValueInstanceID, bareMetalInstanceID)
	if err != nil {
		return nil, fmt.Errorf("failed to set instance ID on BCM device %s: %w", hostname, err)
	}

	if _, err := c.client.UpdateDevice(ctx, raw); err != nil {
		return nil, fmt.Errorf("failed to update BCM device %s: %w", hostname, err)
	}

	return c.verifyAssignment(ctx, hostname, bareMetalInstanceID)
}

func (c *BCMClient) verifyAssignment(ctx context.Context, hostname, bareMetalInstanceID string) (*bcmclient.Device, error) {
	log := ctrllog.FromContext(ctx)

	device, err := c.client.GetDevice(ctx, hostname)
	if err != nil {
		return nil, fmt.Errorf("failed to verify BCM assignment for %s: %w", hostname, err)
	}

	if device == nil {
		log.Info("BCM device disappeared during verify-after-write", "hostname", hostname)
		return nil, nil
	}

	verifiedID, _ := device.ExtraValues[bcmclient.ExtraValueInstanceID].(string)
	if verifiedID != bareMetalInstanceID {
		log.Info("BCM assignment overwritten by concurrent writer", "hostname", hostname,
			"expected", bareMetalInstanceID, "actual", verifiedID)
		return nil, nil
	}

	return device, nil
}

func (c *BCMClient) ensureBMHAndCheckReadiness(ctx context.Context, device *bcmclient.Device, bareMetalInstanceID string) (*Host, error) {
	log := ctrllog.FromContext(ctx)
	hostname := device.Hostname

	// Step 1: Resolve BMC address (unchanged from OSAC-3768)
	bmcAddress, err := c.resolveBMCAddress(ctx, device)
	if err != nil {
		return nil, err
	}

	// Step 2: Check if BMH exists
	exists, err := c.bmhManager.BMHExists(ctx, hostname)
	if err != nil {
		return nil, fmt.Errorf("failed to check BMH existence for %s: %w", hostname, err)
	}

	// Step 3: Create BMH if it doesn't exist
	if !exists {
		credentialsSecret, _ := device.ExtraValues[bcmclient.ExtraValueBMCCredentials].(string)
		if credentialsSecret == "" {
			return nil, fmt.Errorf("BMC credentials Secret not configured for host %q"+
				" — set osac_bmc_credentials_secret in BCM extra_values", hostname)
		}

		params := baremetalhost.CreateParams{
			Name:              hostname,
			BMCAddress:        bmcAddress,
			CredentialsSecret: credentialsSecret,
			BootMACAddress:    device.MAC,
			ConsumerRef: &corev1.ObjectReference{
				APIVersion: "osac.openshift.io/v1alpha1",
				Kind:       "BareMetalInstance",
				Name:       bareMetalInstanceID,
				Namespace:  c.bmhManager.Namespace(),
			},
			Labels: map[string]string{
				Metal3ManagedByLabel: shared.OsacDefaultManagedByValue,
			},
		}

		if err := c.bmhManager.CreateBMH(ctx, params); err != nil {
			return nil, fmt.Errorf("failed to create BareMetalHost for %s: %w", hostname, err)
		}
		log.Info("Created BareMetalHost", "name", hostname)
	} else {
		log.V(1).Info("BareMetalHost already exists, checking readiness", "name", hostname)
	}

	// Step 4: Check readiness (single check, not a blocking poll)
	ready, err := c.bmhManager.IsBMHReady(ctx, hostname)
	if err != nil {
		return nil, fmt.Errorf("failed to check BMH readiness for %s: %w", hostname, err)
	}

	// Step 5: Build Host with Ready field
	host := c.buildHost(device)
	host.Ready = ready

	if !ready {
		log.V(1).Info("BareMetalHost not ready yet, returning Host with Ready=false", "name", hostname)
		return host, nil // Controller will requeue and retry
	}

	log.V(1).Info("BareMetalHost is ready", "name", hostname)
	return host, nil
}

func (c *BCMClient) resolveBMCAddress(ctx context.Context, device *bcmclient.Device) (string, error) {
	log := ctrllog.FromContext(ctx)

	if addr, ok := device.ExtraValues[bcmclient.ExtraValueBMCAddress].(string); ok && addr != "" {
		if err := bmcdiscovery.ValidateBMCAddress(addr); err != nil {
			return "", fmt.Errorf("pre-configured BMC address for host %q is invalid: %w", device.Hostname, err)
		}
		log.V(1).Info("Using pre-configured BMC address (Priority 1)", "hostname", device.Hostname, "address", addr)
		return addr, nil
	}

	bmcInterfaces := make([]bmcdiscovery.DeviceInterface, 0, len(device.Interfaces))
	for _, iface := range device.Interfaces {
		bmcInterfaces = append(bmcInterfaces, bmcdiscovery.DeviceInterface{
			ChildType: iface.ChildType,
			Name:      iface.Name,
			IP:        iface.IP,
		})
	}

	bmcInfo, err := bmcdiscovery.ExtractBMCInfo(bmcInterfaces, bmcInterfaceChildType)
	if err != nil {
		return "", fmt.Errorf("BMC info not available for host %q"+
			" — configure osac_bmc_address in BCM extra_values or register the node with BMC interface data", device.Hostname)
	}

	log.V(1).Info("Resolving BMC address via discovery (Priority 2)", "hostname", device.Hostname, "bmcIP", bmcInfo.IP, "protocol", bmcInfo.Protocol)

	username, password, err := c.readBMCCredentials(ctx, device)
	if err != nil {
		return "", err
	}

	addr, err := bmcdiscovery.Resolve(ctx, bmcInfo, device.MAC, username, password, c.bmcDiscoverer)
	if err != nil {
		return "", fmt.Errorf("BMC address discovery failed for host %q: %w", device.Hostname, err)
	}

	if err := c.cacheBMCAddress(ctx, device, addr); err != nil {
		log.Info("Failed to cache discovered BMC address in BCM, will rediscover on next reconcile",
			"hostname", device.Hostname, "error", err)
	}

	return addr, nil
}

func (c *BCMClient) readBMCCredentials(ctx context.Context, device *bcmclient.Device) (string, string, error) {
	credentialsSecret, _ := device.ExtraValues[bcmclient.ExtraValueBMCCredentials].(string)
	if credentialsSecret == "" {
		return "", "", fmt.Errorf("BMC credentials Secret not configured for host %q"+
			" — set osac_bmc_credentials_secret in BCM extra_values", device.Hostname)
	}

	username, password, err := c.bmhManager.ReadBMCCredentials(ctx, credentialsSecret)
	if err != nil {
		return "", "", fmt.Errorf("failed to read BMC credentials for host %q: %w", device.Hostname, err)
	}

	return username, password, nil
}

func (c *BCMClient) cacheBMCAddress(ctx context.Context, device *bcmclient.Device, addr string) error {
	raw, err := bcmclient.SetExtraValue(device.Raw, bcmclient.ExtraValueBMCAddress, addr)
	if err != nil {
		return err
	}
	_, err = c.client.UpdateDevice(ctx, raw)
	return err
}

func (c *BCMClient) buildHost(device *bcmclient.Device) *Host {
	resourceClass, _ := device.ExtraValues[bcmclient.ExtraValueResourceClass].(string)
	return &Host{
		InventoryHostID: fmt.Sprintf("%s/%s", c.bmhManager.Namespace(), device.Hostname),
		Name:            device.Hostname,
		HostType:        resourceClass,
		HostClass:       c.hostClass,
		ManagedBy:       shared.OsacDefaultManagedByValue,
	}
}

// UnassignHost is implemented in OSAC-3771.
func (c *BCMClient) UnassignHost(_ context.Context, _ string, _ []string) error {
	return fmt.Errorf("bcm UnassignHost not implemented")
}

// GetHostNICs reads all NIC MAC addresses from the BareMetalHost CR hardware inspection data.
// inventoryHostID must be in namespace/hostname format where hostname is the BMH name.
// Reading from the BMH CR avoids a costly GetDevices round-trip to the BCM API.
// Returns nil, nil when the BMH has no hardware inspection data (caller treats this as "NIC data unavailable").
func (c *BCMClient) GetHostNICs(ctx context.Context, inventoryHostID string) ([]HostNIC, error) {
	_, bmhName, err := ParseHostID(inventoryHostID)
	if err != nil {
		return nil, err
	}

	macs, err := c.bmhManager.GetHardwareNICs(ctx, bmhName)
	if err != nil {
		return nil, fmt.Errorf("GetHostNICs: failed to get BMH %s: %w", bmhName, err)
	}
	if len(macs) == 0 {
		return nil, nil
	}
	nics := make([]HostNIC, 0, len(macs))
	for _, mac := range macs {
		nics = append(nics, HostNIC{MAC: mac})
	}
	return nics, nil
}
