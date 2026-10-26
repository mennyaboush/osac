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
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	. "github.com/onsi/ginkgo/v2" //nolint:revive,staticcheck
	. "github.com/onsi/gomega"    //nolint:revive,staticcheck
	"go.uber.org/mock/gomock"

	"github.com/osac-project/osac/bare-metal-fulfillment-operator/internal/baremetalhost"
	"github.com/osac-project/osac/bare-metal-fulfillment-operator/internal/netboxclient"
	"github.com/osac-project/osac/bare-metal-fulfillment-operator/internal/shared"
)

const testNetBoxHostClass = "metal3"

var _ = Describe("NetBox inventory client", func() {
	Describe("ParseNetBoxOptions", func() {
		DescribeTable("rejects invalid options",
			func(options map[string]any, wantErr string) {
				_, err := ParseNetBoxOptions(options)
				Expect(err).To(MatchError(ContainSubstring(wantErr)))
			},
			Entry("missing options", map[string]any{}, "netbox options not found in config"),
			Entry("wrong value type", map[string]any{"netbox": "not-a-map"}, "failed to parse netbox options"),
			Entry("missing URL", map[string]any{"netbox": map[string]any{"tokenFile": "/var/run/secrets/netbox/token"}}, "netbox url is required in config"),
			Entry("missing token file", map[string]any{"netbox": map[string]any{"url": "https://netbox.example.test"}}, "netbox tokenFile is required in config"),
		)

		It("parses valid options", func() {
			options := map[string]any{"netbox": map[string]any{
				"url":               "https://netbox.example.test/",
				"tokenFile":         "/var/run/secrets/netbox/token",
				"caFile":            "/var/run/secrets/netbox/ca.crt",
				"allowInsecureHTTP": true,
			}}

			got, err := ParseNetBoxOptions(options)

			Expect(err).NotTo(HaveOccurred())
			Expect(got).To(Equal(&NetBoxClientConfig{
				URL:               "https://netbox.example.test/",
				TokenFile:         "/var/run/secrets/netbox/token",
				CAFile:            "/var/run/secrets/netbox/ca.crt",
				AllowInsecureHTTP: true,
			}))
		})

		It("rejects values that cannot be marshaled", func() {
			_, err := ParseNetBoxOptions(map[string]any{"netbox": make(chan int)})

			Expect(err).To(MatchError(ContainSubstring("failed to parse netbox options")))
		})
	})

	Describe("NewNetBoxClient", func() {
		It("retains the injected API, manager, and host class", func() {
			tokenFile := filepath.Join(GinkgoT().TempDir(), "token")
			Expect(os.WriteFile(tokenFile, []byte("test-token\n"), 0o600)).To(Succeed())

			api, err := NewNetBoxAPI(&Config{Options: map[string]any{"netbox": map[string]any{
				"url":       "https://netbox.example.test/",
				"tokenFile": tokenFile,
			}}})
			Expect(err).NotTo(HaveOccurred())
			Expect(api).NotTo(BeNil())

			manager := baremetalhost.NewManager(nil, nil, "metal3-system")
			client := NewNetBoxClient(api, manager, testNetBoxHostClass)

			Expect(client.api).To(BeIdenticalTo(api))
			Expect(client.bmhManager).To(BeIdenticalTo(manager))
			Expect(client.bmhManager.Namespace()).To(Equal("metal3-system"))
			Expect(client.hostClass).To(Equal(testNetBoxHostClass))
		})
	})

	Describe("NewNetBoxAPI", func() {
		DescribeTable("rejects invalid configuration",
			func(config *Config, wantErr string) {
				_, err := NewNetBoxAPI(config)
				Expect(err).To(MatchError(ContainSubstring(wantErr)))
			},
			Entry("nil config", (*Config)(nil), "netbox inventory config is required"),
			Entry("missing NetBox options", &Config{}, "netbox options not found in config"),
			Entry("HTTP URL without opt-in", &Config{Options: map[string]any{"netbox": map[string]any{
				"url":       "http://netbox.example.test",
				"tokenFile": "/unused/token",
			}}}, "NetBox HTTP endpoints require AllowInsecureHTTP"),
		)

		It("rejects an unreadable token file", func() {
			tokenFile := filepath.Join(GinkgoT().TempDir(), "missing-token")
			config := &Config{Options: map[string]any{"netbox": map[string]any{
				"url":       "https://netbox.example.test",
				"tokenFile": tokenFile,
			}}}

			_, err := NewNetBoxAPI(config)

			Expect(err).To(MatchError(ContainSubstring("token file is missing or invalid")))
		})
	})

	Describe("stub methods", func() {
		It("return not-implemented errors", func() {
			client := &NetBoxClient{}
			ctx := context.Background()

			err := client.UnassignHost(ctx, "baremetal/netbox-42", []string{"192.0.2.42"})
			Expect(errors.Is(err, errNetBoxClientNotImplemented)).To(BeTrue())

		})
	})
})

type selectorQueryTestAPI struct {
	deviceQueries    int
	deviceQuery      netboxclient.DeviceQuery
	devices          []netboxclient.Device
	deviceErr        error
	deviceVisits     int
	customFieldReads int
	deviceSnapshot   netboxclient.DeviceSnapshot
	deviceSnapshots  []netboxclient.DeviceSnapshot
	deviceReadCalls  int
	deviceReadIDs    []string
	patchCalls       int
	patchDeviceID    string
	patch            netboxclient.DevicePatch
	patchETag        string
	patchSnapshot    netboxclient.DeviceSnapshot
	patchErr         error
}

func (a *selectorQueryTestAPI) ForEachDevice(
	_ context.Context,
	query netboxclient.DeviceQuery,
	visit func(netboxclient.Device) (bool, error),
) error {
	a.deviceQueries++
	a.deviceQuery = maps.Clone(query)
	if a.deviceErr != nil {
		return a.deviceErr
	}
	for _, device := range a.devices {
		a.deviceVisits++
		keepGoing, err := visit(device)
		if err != nil {
			return err
		}
		if !keepGoing {
			return nil
		}
	}
	return nil
}

func (a *selectorQueryTestAPI) ForEachDeviceCustomField(
	context.Context,
	func(netboxclient.CustomField) (bool, error),
) error {
	a.customFieldReads++
	return errors.New("unexpected custom-field metadata lookup")
}

func (a *selectorQueryTestAPI) GetDevice(_ context.Context, id string) (netboxclient.DeviceSnapshot, error) {
	a.deviceReadCalls++
	a.deviceReadIDs = append(a.deviceReadIDs, id)
	if index := a.deviceReadCalls - 1; index < len(a.deviceSnapshots) {
		return a.deviceSnapshots[index], nil
	}
	return a.deviceSnapshot, nil
}

func (*selectorQueryTestAPI) ForEachDeviceInterface(
	context.Context,
	string,
	func(netboxclient.DeviceInterface) (bool, error),
) error {
	return errors.New("unexpected interface listing")
}

func (a *selectorQueryTestAPI) PatchDevice(
	_ context.Context,
	id string,
	patch netboxclient.DevicePatch,
	etag string,
) (netboxclient.DeviceSnapshot, error) {
	a.patchCalls++
	a.patchDeviceID = id
	a.patch = patch
	a.patchETag = etag
	return a.patchSnapshot, a.patchErr
}

var _ = Describe("NetBox selector query", func() {
	Describe("FindFreeHost", func() {
		It("returns an error when the Metal3 namespace is missing without querying NetBox", func() {
			api := &selectorQueryTestAPI{}
			client := NewNetBoxClient(api, baremetalhost.NewManager(nil, nil, ""), testNetBoxHostClass)

			host, err := client.FindFreeHost(context.Background(), nil)

			Expect(host).To(BeNil())
			Expect(err).To(MatchError("NetBox inventory requires a Metal3 namespace"))
			Expect(api.deviceQueries).To(BeZero())
		})

		It("queries with required free-host filters and selector fields", func() {
			api := &selectorQueryTestAPI{
				devices: []netboxclient.Device{
					{ID: "46", Name: "netbox-device-46"},
					{ID: "47", Name: "netbox-device-47"},
				},
			}
			client := NewNetBoxClient(api, testNetBoxSelectorBMHManager(), testNetBoxHostClass)
			selector := map[string]string{
				"cpu_cores":      "9007199254740993",
				"accelerated":    "true",
				"placement_zone": "Lab A",
				"accelerator":    "a100",
			}

			host, err := client.FindFreeHost(context.Background(), selector)

			Expect(err).NotTo(HaveOccurred())
			Expect(host).To(Equal(&Host{
				InventoryHostID: "metal3-system/netbox-46",
				Name:            "netbox-46",
				HostClass:       testNetBoxHostClass,
				ProvisionState:  shared.OsacDefaultProvisionStateValue,
				ManagedBy:       shared.OsacDefaultManagedByValue,
				Ready:           true,
			}))
			Expect(api.customFieldReads).To(BeZero())
			Expect(api.deviceQueries).To(Equal(1))
			Expect(api.deviceVisits).To(Equal(1))
			Expect(api.deviceQuery).To(Equal(netboxclient.DeviceQuery{
				"status":                     "staged",
				"cf_osac_managed":            "true",
				"cf_osac_instance_id__empty": "true",
				"cf_cpu_cores":               "9007199254740993",
				"cf_accelerated":             "true",
				"cf_placement_zone":          "Lab A",
				"cf_accelerator":             "a100",
			}))
		})

		It("keeps the required managed filter when the selector requests another value", func() {
			api := &selectorQueryTestAPI{}
			client := NewNetBoxClient(api, testNetBoxSelectorBMHManager(), testNetBoxHostClass)

			_, err := client.FindFreeHost(context.Background(), map[string]string{"osac_managed": "false"})

			Expect(err).NotTo(HaveOccurred())
			Expect(api.deviceQueries).To(Equal(1))
			Expect(api.deviceQuery["cf_osac_managed"]).To(Equal("true"))
		})

		It("queries the fixed free-host filters when the selector is empty", func() {
			api := &selectorQueryTestAPI{}
			client := NewNetBoxClient(api, testNetBoxSelectorBMHManager(), testNetBoxHostClass)

			host, err := client.FindFreeHost(context.Background(), nil)

			Expect(host).To(BeNil())
			Expect(err).NotTo(HaveOccurred())
			Expect(api.customFieldReads).To(BeZero())
			Expect(api.deviceQueries).To(Equal(1))
			Expect(api.deviceQuery).To(Equal(netboxclient.DeviceQuery{
				"status":                     "staged",
				"cf_osac_managed":            "true",
				"cf_osac_instance_id__empty": "true",
			}))
		})

		It("returns device-list errors", func() {
			apiError := errors.New("device endpoint unavailable")
			api := &selectorQueryTestAPI{deviceErr: apiError}
			client := NewNetBoxClient(api, testNetBoxSelectorBMHManager(), testNetBoxHostClass)

			host, err := client.FindFreeHost(context.Background(), map[string]string{"placement_zone": "west"})

			Expect(host).To(BeNil())
			Expect(err).To(MatchError(ContainSubstring("failed to search NetBox for a free host")))
			Expect(errors.Is(err, apiError)).To(BeTrue())
			Expect(api.customFieldReads).To(BeZero())
			Expect(api.deviceQueries).To(Equal(1))
		})
	})

	Describe("Capability selector filters", func() {
		DescribeTable("prefixes selector fields as NetBox custom-field filters",
			func(key string) {
				query := buildFreeHostQuery(map[string]string{key: "a100"})

				Expect(query["cf_"+key]).To(Equal("a100"))
			},
			Entry("hyphenated name", "gpu-model"),
			Entry("name longer than 50 characters", strings.Repeat("x", 51)),
			Entry("name beginning with the query prefix", "cf_gpu_cores"),
		)

		DescribeTable("passes selector values unchanged",
			func(value string) {
				query := buildFreeHostQuery(map[string]string{"capability": value})

				Expect(query["cf_capability"]).To(Equal(value))
			},
			Entry("integer value", "16"),
			Entry("integer formatting", "016"),
			Entry("Boolean value", "false"),
			Entry("Boolean casing", "TRUE"),
			Entry("empty text", ""),
			Entry("text null string", "null"),
			Entry("text whitespace", " a100 "),
			Entry("select stored value", "a100"),
		)

	})
})

var _ = Describe("NetBox assignment eligibility", func() {
	It("trusts the managed filter used when the device was selected", func() {
		freeDevice := testNetBoxAssignmentSnapshot(netBoxStatusStaged, "")
		freeDevice.Device.CustomFields["osac_managed"] = false
		claimedDevice := testNetBoxAssignmentSnapshot(netBoxStatusActive, "bmi-123")
		claimedDevice.Device.CustomFields["osac_managed"] = false
		api := &selectorQueryTestAPI{deviceSnapshot: freeDevice, patchSnapshot: claimedDevice}
		client := NewNetBoxClient(api, testNetBoxSelectorBMHManager(), testNetBoxHostClass)

		host, err := client.AssignHost(context.Background(), "metal3-system/netbox-46", "bmi-123", nil)

		Expect(err).NotTo(HaveOccurred())
		Expect(host).To(Equal(expectedTestNetBoxAssignedHost("bmi-123")))
		Expect(api.patchCalls).To(Equal(1))
	})

	It("does not claim a device that became active without an owner", func() {
		api := &selectorQueryTestAPI{
			deviceSnapshot: testNetBoxAssignmentSnapshot(netBoxStatusActive, ""),
		}
		client := NewNetBoxClient(api, testNetBoxSelectorBMHManager(), testNetBoxHostClass)

		host, err := client.AssignHost(context.Background(), "metal3-system/netbox-46", "bmi-123", nil)

		Expect(host).To(BeNil())
		Expect(err).To(MatchError(ContainSubstring("active without an assigned instance")))
		Expect(api.patchCalls).To(BeZero())
	})

	It("claims a free managed device with its ETag and confirms the assignment", func() {
		freeDevice := testNetBoxAssignmentSnapshot(netBoxStatusStaged, "")
		api := &selectorQueryTestAPI{
			deviceSnapshot: freeDevice,
			patchSnapshot:  testNetBoxAssignmentSnapshot(netBoxStatusActive, "bmi-123"),
		}
		client := NewNetBoxClient(api, testNetBoxSelectorBMHManager(), testNetBoxHostClass)

		host, err := client.AssignHost(context.Background(), "metal3-system/netbox-46", "bmi-123", nil)

		Expect(err).NotTo(HaveOccurred())
		Expect(host).To(Equal(expectedTestNetBoxAssignedHost("bmi-123")))
		Expect(api.deviceReadIDs).To(Equal([]string{"46"}))
		Expect(api.patchCalls).To(Equal(1))
		Expect(api.patchDeviceID).To(Equal("46"))
		Expect(api.patchETag).To(Equal(freeDevice.ETag))
		Expect(api.patch.Status).NotTo(BeNil())
		Expect(*api.patch.Status).To(Equal(netBoxStatusActive))
		Expect(api.patch.CustomFields).To(Equal(map[string]interface{}{"osac_instance_id": "bmi-123"}))
	})

	It("returns an existing assignment without patching the device", func() {
		api := &selectorQueryTestAPI{
			deviceSnapshot: testNetBoxAssignmentSnapshot(netBoxStatusActive, "bmi-123"),
		}
		client := NewNetBoxClient(api, testNetBoxSelectorBMHManager(), testNetBoxHostClass)

		host, err := client.AssignHost(context.Background(), "metal3-system/netbox-46", "bmi-123", nil)

		Expect(err).NotTo(HaveOccurred())
		Expect(host).To(Equal(expectedTestNetBoxAssignedHost("bmi-123")))
		Expect(api.patchCalls).To(BeZero())
	})

	It("propagates the client error for a free device without an ETag", func() {
		freeDevice := testNetBoxAssignmentSnapshot(netBoxStatusStaged, "")
		freeDevice.ETag = ""
		api := &selectorQueryTestAPI{
			deviceSnapshot: freeDevice,
			patchErr:       &netboxclient.APIError{Kind: netboxclient.ErrorKindInvalidETag},
		}
		client := NewNetBoxClient(api, testNetBoxSelectorBMHManager(), testNetBoxHostClass)

		host, err := client.AssignHost(context.Background(), "metal3-system/netbox-46", "bmi-123", nil)

		Expect(host).To(BeNil())
		Expect(err).To(MatchError(ContainSubstring("NetBox device ETag is missing or invalid")))
		Expect(api.patchCalls).To(Equal(1))
		Expect(api.patchETag).To(BeEmpty())
	})

	It("returns non-conflict PATCH errors", func() {
		patchErr := errors.New("NetBox unavailable")
		api := &selectorQueryTestAPI{
			deviceSnapshot: testNetBoxAssignmentSnapshot(netBoxStatusStaged, ""),
			patchErr:       patchErr,
		}
		client := NewNetBoxClient(api, testNetBoxSelectorBMHManager(), testNetBoxHostClass)

		host, err := client.AssignHost(context.Background(), "metal3-system/netbox-46", "bmi-123", nil)

		Expect(host).To(BeNil())
		Expect(err).To(MatchError(ContainSubstring("failed to claim NetBox device")))
		Expect(errors.Is(err, patchErr)).To(BeTrue())
		Expect(api.patchCalls).To(Equal(1))
	})

	It("returns an error when a successful PATCH does not confirm the assignment", func() {
		freeDevice := testNetBoxAssignmentSnapshot(netBoxStatusStaged, "")
		api := &selectorQueryTestAPI{
			deviceSnapshot: freeDevice,
			patchSnapshot:  freeDevice,
		}
		client := NewNetBoxClient(api, testNetBoxSelectorBMHManager(), testNetBoxHostClass)

		host, err := client.AssignHost(context.Background(), "metal3-system/netbox-46", "bmi-123", nil)

		Expect(host).To(BeNil())
		Expect(err).To(MatchError(ContainSubstring("did not confirm the host assignment")))
		Expect(api.patchCalls).To(Equal(1))
	})

	DescribeTable("reconciles a claim after a 412 response",
		func(latest netboxclient.DeviceSnapshot, wantHost bool, wantErr string) {
			api := &selectorQueryTestAPI{
				deviceSnapshots: []netboxclient.DeviceSnapshot{
					testNetBoxAssignmentSnapshot(netBoxStatusStaged, ""),
					latest,
				},
				patchErr: &netboxclient.APIError{
					Kind:       netboxclient.ErrorKindConflict,
					StatusCode: http.StatusPreconditionFailed,
				},
			}
			client := NewNetBoxClient(api, testNetBoxSelectorBMHManager(), testNetBoxHostClass)

			host, err := client.AssignHost(context.Background(), "metal3-system/netbox-46", "bmi-123", nil)

			if wantHost {
				Expect(host).To(Equal(expectedTestNetBoxAssignedHost("bmi-123")))
			} else {
				Expect(host).To(BeNil())
			}
			if wantErr != "" {
				Expect(err).To(MatchError(ContainSubstring(wantErr)))
			} else {
				Expect(err).NotTo(HaveOccurred())
			}
			Expect(api.patchCalls).To(Equal(1))
			Expect(api.deviceReadIDs).To(Equal([]string{"46", "46"}))
		},
		Entry("now owned by this instance", testNetBoxAssignmentSnapshot(netBoxStatusActive, "bmi-123"), true, ""),
		Entry("now owned by another instance", testNetBoxAssignmentSnapshot(netBoxStatusActive, "bmi-456"), false, ""),
		Entry("still free", testNetBoxAssignmentSnapshot(netBoxStatusStaged, ""), false, "changed during assignment"),
	)
})

func testNetBoxAssignmentSnapshot(status, instanceID string) netboxclient.DeviceSnapshot {
	return netboxclient.DeviceSnapshot{
		Device: netboxclient.Device{
			ID:     "46",
			Status: status,
			CustomFields: map[string]interface{}{
				"osac_managed":     true,
				"osac_instance_id": instanceID,
			},
		},
		ETag: `W/"device-revision-1"`,
	}
}

func expectedTestNetBoxAssignedHost(instanceID string) *Host {
	return &Host{
		InventoryHostID:     "metal3-system/netbox-46",
		Name:                "netbox-46",
		HostClass:           testNetBoxHostClass,
		ProvisionState:      shared.OsacDefaultProvisionStateValue,
		ManagedBy:           shared.OsacDefaultManagedByValue,
		Ready:               true,
		BareMetalInstanceID: instanceID,
	}
}

func testNetBoxSelectorBMHManager() *baremetalhost.Manager {
	return baremetalhost.NewManager(nil, nil, "metal3-system")
}

var _ = Describe("NetBox host NIC reads", Label("OSAC-5953"), func() {
	DescribeTable("ID-01 accepts canonical saved host IDs",
		func(inventoryHostID, bmhName, deviceID string) {
			ctx := context.Background()
			manager := baremetalhost.NewMockBMHLifecycleManager(gomock.NewController(GinkgoT()))
			manager.EXPECT().Namespace().Return("baremetal").Times(2)
			manager.EXPECT().GetHardwareNICs(gomock.Eq(ctx), bmhName).
				Return([]string{"AA:BB:CC:DD:EE:01"}, nil)
			api := &nicReadTestAPI{}
			var requestedID string
			api.interfaceList = func(gotContext context.Context, gotDeviceID string, visit func(netboxclient.DeviceInterface) (bool, error)) error {
				Expect(gotContext).To(Equal(ctx))
				requestedID = gotDeviceID
				_, err := visit(netboxclient.DeviceInterface{
					ID: "501", Name: "data-0", PrimaryMAC: "AA:BB:CC:DD:EE:01",
				})
				return err
			}

			client := NewNetBoxClient(api, manager, testNetBoxHostClass)
			nics, err := client.GetHostNICs(ctx, inventoryHostID)

			Expect(err).NotTo(HaveOccurred())
			Expect(nics).To(Equal([]HostNIC{{MAC: "aa:bb:cc:dd:ee:01"}}))

			logicalMACs, err := client.GetHostLogicalPortMACs(ctx, inventoryHostID)

			Expect(err).NotTo(HaveOccurred())
			Expect(logicalMACs).To(Equal(map[string]string{"data-0": "aa:bb:cc:dd:ee:01"}))
			Expect(requestedID).To(Equal(deviceID))
			Expect(api.calls).To(Equal(1))
		},
		Entry("netbox ID 1", "baremetal/netbox-1", "netbox-1", "1"),
		Entry("netbox ID 42", "baremetal/netbox-42", "netbox-42", "42"),
		Entry("maximum int32 ID", "baremetal/netbox-2147483647", "netbox-2147483647", "2147483647"),
	)

	DescribeTable("ID-02 through ID-05 reject malformed saved host IDs before dependency I/O",
		func(inventoryHostID string) {
			manager := baremetalhost.NewMockBMHLifecycleManager(gomock.NewController(GinkgoT()))
			manager.EXPECT().Namespace().AnyTimes().Return("baremetal")
			api := &nicReadTestAPI{}

			client := NewNetBoxClient(api, manager, testNetBoxHostClass)
			nics, err := client.GetHostNICs(context.Background(), inventoryHostID)

			Expect(err).To(HaveOccurred())
			Expect(errors.Is(err, errNetBoxClientNotImplemented)).To(BeFalse())
			Expect(nics).To(BeNil())

			logicalMACs, logicalErr := client.GetHostLogicalPortMACs(context.Background(), inventoryHostID)

			Expect(logicalErr).To(HaveOccurred())
			Expect(errors.Is(logicalErr, errNetBoxClientNotImplemented)).To(BeFalse())
			Expect(logicalMACs).To(BeNil())
			Expect(api.calls).To(BeZero())
		},
		Entry("ID-02 empty ID", ""),
		Entry("ID-02 name without namespace", "netbox-42"),
		Entry("ID-02 empty namespace", "/netbox-42"),
		Entry("ID-02 empty name", "baremetal/"),
		Entry("ID-02 extra path segment", "baremetal/netbox-42/extra"),
		Entry("ID-03 wrong prefix", "baremetal/host-42"),
		Entry("ID-03 case-sensitive prefix", "baremetal/NETBOX-42"),
		Entry("ID-03 empty suffix", "baremetal/netbox-"),
		Entry("ID-04 nonnumeric suffix", "baremetal/netbox-abc"),
		Entry("ID-04 zero suffix", "baremetal/netbox-0"),
		Entry("ID-04 negative suffix", "baremetal/netbox--1"),
		Entry("ID-04 plus sign", "baremetal/netbox-+42"),
		Entry("ID-04 leading zero", "baremetal/netbox-042"),
		Entry("ID-04 trailing whitespace", "baremetal/netbox-42 "),
		Entry("ID-04 int32 overflow", "baremetal/netbox-2147483648"),
		Entry("ID-05 different namespace", "other/netbox-42"),
	)

	It("ID-06 rejects a nil receiver", func() {
		var client *NetBoxClient

		ctx := context.Background()
		nics, err := client.GetHostNICs(ctx, "baremetal/netbox-42")

		Expect(err).To(HaveOccurred())
		Expect(errors.Is(err, errNetBoxClientNotImplemented)).To(BeFalse())
		Expect(nics).To(BeNil())
		logicalMACs, logicalErr := client.GetHostLogicalPortMACs(ctx, "baremetal/netbox-42")
		Expect(logicalErr).To(HaveOccurred())
		Expect(errors.Is(logicalErr, errNetBoxClientNotImplemented)).To(BeFalse())
		Expect(logicalMACs).To(BeNil())
	})

	It("ID-06 rejects a zero-value client", func() {
		ctx := context.Background()
		nics, err := (&NetBoxClient{}).GetHostNICs(ctx, "baremetal/netbox-42")

		Expect(err).To(HaveOccurred())
		Expect(errors.Is(err, errNetBoxClientNotImplemented)).To(BeFalse())
		Expect(nics).To(BeNil())
		logicalMACs, logicalErr := (&NetBoxClient{}).GetHostLogicalPortMACs(ctx, "baremetal/netbox-42")
		Expect(logicalErr).To(HaveOccurred())
		Expect(errors.Is(logicalErr, errNetBoxClientNotImplemented)).To(BeFalse())
		Expect(logicalMACs).To(BeNil())
	})

	It("ID-06 rejects a missing manager", func() {
		api := &nicReadTestAPI{}
		client := NewNetBoxClient(api, nil, testNetBoxHostClass)

		ctx := context.Background()
		nics, err := client.GetHostNICs(ctx, "baremetal/netbox-42")

		Expect(err).To(HaveOccurred())
		Expect(errors.Is(err, errNetBoxClientNotImplemented)).To(BeFalse())
		Expect(nics).To(BeNil())
		logicalMACs, logicalErr := client.GetHostLogicalPortMACs(ctx, "baremetal/netbox-42")
		Expect(logicalErr).To(HaveOccurred())
		Expect(errors.Is(logicalErr, errNetBoxClientNotImplemented)).To(BeFalse())
		Expect(logicalMACs).To(BeNil())
		Expect(api.calls).To(BeZero())
	})

	It("ID-06 rejects an empty configured namespace", func() {
		manager := baremetalhost.NewMockBMHLifecycleManager(gomock.NewController(GinkgoT()))
		manager.EXPECT().Namespace().AnyTimes().Return("")
		api := &nicReadTestAPI{}
		client := NewNetBoxClient(api, manager, testNetBoxHostClass)

		ctx := context.Background()
		nics, err := client.GetHostNICs(ctx, "baremetal/netbox-42")

		Expect(err).To(HaveOccurred())
		Expect(errors.Is(err, errNetBoxClientNotImplemented)).To(BeFalse())
		Expect(nics).To(BeNil())
		logicalMACs, logicalErr := client.GetHostLogicalPortMACs(ctx, "baremetal/netbox-42")
		Expect(logicalErr).To(HaveOccurred())
		Expect(errors.Is(logicalErr, errNetBoxClientNotImplemented)).To(BeFalse())
		Expect(logicalMACs).To(BeNil())
		Expect(api.calls).To(BeZero())
	})

	It("ID-07 reads physical NICs without a NetBox API", func() {
		ctx := context.Background()
		manager := baremetalhost.NewMockBMHLifecycleManager(gomock.NewController(GinkgoT()))
		manager.EXPECT().Namespace().Return("baremetal").Times(2)
		manager.EXPECT().GetHardwareNICs(gomock.Eq(ctx), "netbox-42").
			Return([]string{"AA:BB:CC:DD:EE:01"}, nil)

		client := NewNetBoxClient(nil, manager, testNetBoxHostClass)
		nics, err := client.GetHostNICs(ctx, "baremetal/netbox-42")

		Expect(err).NotTo(HaveOccurred())
		Expect(nics).To(Equal([]HostNIC{{MAC: "aa:bb:cc:dd:ee:01"}}))
		logicalMACs, logicalErr := client.GetHostLogicalPortMACs(ctx, "baremetal/netbox-42")
		Expect(logicalErr).To(HaveOccurred())
		Expect(errors.Is(logicalErr, errNetBoxClientNotImplemented)).To(BeFalse())
		Expect(logicalMACs).To(BeNil())
	})

	It("ID-08 returns pre-cancelled context without reading dependencies", func() {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		manager := baremetalhost.NewMockBMHLifecycleManager(gomock.NewController(GinkgoT()))
		manager.EXPECT().Namespace().Return("baremetal").Times(2)
		api := &nicReadTestAPI{}

		client := NewNetBoxClient(api, manager, testNetBoxHostClass)
		nics, err := client.GetHostNICs(ctx, "baremetal/netbox-42")

		Expect(errors.Is(err, context.Canceled)).To(BeTrue())
		Expect(nics).To(BeNil())
		logicalMACs, logicalErr := client.GetHostLogicalPortMACs(ctx, "baremetal/netbox-42")
		Expect(errors.Is(logicalErr, context.Canceled)).To(BeTrue())
		Expect(logicalMACs).To(BeNil())
		Expect(api.calls).To(BeZero())
	})

	It("PHY-01 preserves manager order and lowercases physical MACs", func() {
		ctx := context.Background()
		manager := baremetalhost.NewMockBMHLifecycleManager(gomock.NewController(GinkgoT()))
		manager.EXPECT().Namespace().Return("baremetal")
		manager.EXPECT().GetHardwareNICs(gomock.Eq(ctx), "netbox-42").
			Return([]string{"AA:BB:CC:DD:EE:01", "52:54:00:16:04:83"}, nil)
		api := &nicReadTestAPI{}

		nics, err := NewNetBoxClient(api, manager, testNetBoxHostClass).
			GetHostNICs(ctx, "baremetal/netbox-42")

		Expect(err).NotTo(HaveOccurred())
		Expect(nics).To(Equal([]HostNIC{
			{MAC: "aa:bb:cc:dd:ee:01"},
			{MAC: "52:54:00:16:04:83"},
		}))
		Expect(api.calls).To(BeZero())
	})

	DescribeTable("PHY-02 normalizes missing hardware data to nil",
		func(macs []string) {
			ctx := context.Background()
			manager := baremetalhost.NewMockBMHLifecycleManager(gomock.NewController(GinkgoT()))
			manager.EXPECT().Namespace().Return("baremetal")
			manager.EXPECT().GetHardwareNICs(gomock.Eq(ctx), "netbox-42").Return(macs, nil)

			nics, err := NewNetBoxClient(nil, manager, testNetBoxHostClass).
				GetHostNICs(ctx, "baremetal/netbox-42")

			Expect(err).NotTo(HaveOccurred())
			Expect(nics).To(BeNil())
		},
		Entry("nil slice", []string(nil)),
		Entry("empty slice", []string{}),
		Entry("only empty MACs", []string{"", ""}),
	)

	It("PHY-03 skips empty MACs without changing populated values", func() {
		ctx := context.Background()
		manager := baremetalhost.NewMockBMHLifecycleManager(gomock.NewController(GinkgoT()))
		manager.EXPECT().Namespace().Return("baremetal")
		manager.EXPECT().GetHardwareNICs(gomock.Eq(ctx), "netbox-42").
			Return([]string{"", "AA:BB:CC:DD:EE:01", ""}, nil)

		nics, err := NewNetBoxClient(nil, manager, testNetBoxHostClass).
			GetHostNICs(ctx, "baremetal/netbox-42")

		Expect(err).NotTo(HaveOccurred())
		Expect(nics).To(Equal([]HostNIC{{MAC: "aa:bb:cc:dd:ee:01"}}))
	})

	It("PHY-04 preserves the manager error and returns no partial result", func() {
		ctx := context.Background()
		sentinel := errors.New("hardware inspection unavailable")
		manager := baremetalhost.NewMockBMHLifecycleManager(gomock.NewController(GinkgoT()))
		manager.EXPECT().Namespace().Return("baremetal")
		manager.EXPECT().GetHardwareNICs(gomock.Eq(ctx), "netbox-42").
			Return([]string{"AA:BB:CC:DD:EE:01"}, sentinel)

		nics, err := NewNetBoxClient(nil, manager, testNetBoxHostClass).
			GetHostNICs(ctx, "baremetal/netbox-42")

		Expect(errors.Is(err, sentinel)).To(BeTrue())
		Expect(nics).To(BeNil())
	})

	It("PHY-05 preserves manager cancellation", func() {
		ctx := context.Background()
		manager := baremetalhost.NewMockBMHLifecycleManager(gomock.NewController(GinkgoT()))
		manager.EXPECT().Namespace().Return("baremetal")
		manager.EXPECT().GetHardwareNICs(gomock.Eq(ctx), "netbox-42").
			Return(nil, context.DeadlineExceeded)

		nics, err := NewNetBoxClient(nil, manager, testNetBoxHostClass).
			GetHostNICs(ctx, "baremetal/netbox-42")

		Expect(errors.Is(err, context.DeadlineExceeded)).To(BeTrue())
		Expect(nics).To(BeNil())
	})

	It("PHY-06 does not query NetBox for physical NICs", func() {
		ctx := context.Background()
		manager := baremetalhost.NewMockBMHLifecycleManager(gomock.NewController(GinkgoT()))
		manager.EXPECT().Namespace().Return("baremetal")
		manager.EXPECT().GetHardwareNICs(gomock.Eq(ctx), "netbox-42").
			Return([]string{"AA:BB:CC:DD:EE:01"}, nil)
		api := &nicReadTestAPI{}

		_, err := NewNetBoxClient(api, manager, testNetBoxHostClass).
			GetHostNICs(ctx, "baremetal/netbox-42")

		Expect(err).NotTo(HaveOccurred())
		Expect(api.calls).To(BeZero())
	})

	It("PHY-07 lowercases opaque hardware values without parsing them", func() {
		ctx := context.Background()
		manager := baremetalhost.NewMockBMHLifecycleManager(gomock.NewController(GinkgoT()))
		manager.EXPECT().Namespace().Return("baremetal")
		manager.EXPECT().GetHardwareNICs(gomock.Eq(ctx), "netbox-42").
			Return([]string{"Opaque-MAC Value"}, nil)

		nics, err := NewNetBoxClient(nil, manager, testNetBoxHostClass).
			GetHostNICs(ctx, "baremetal/netbox-42")

		Expect(err).NotTo(HaveOccurred())
		Expect(nics).To(Equal([]HostNIC{{MAC: "opaque-mac value"}}))
	})

	It("LOG-01 uses the exact native name when no alias is configured", func() {
		client, api := newNetBoxLogicalMACTestClient()
		configureNetBoxInterfaces(api, netboxInterfaceForTest("501", "data-0", "AA:BB:CC:DD:EE:01", nil))

		macs, err := client.GetHostLogicalPortMACs(context.Background(), "baremetal/netbox-42")

		Expect(err).NotTo(HaveOccurred())
		Expect(macs).To(Equal(map[string]string{"data-0": "aa:bb:cc:dd:ee:01"}))
	})

	It("LOG-02 uses an explicit alias instead of exposing the native name", func() {
		client, api := newNetBoxLogicalMACTestClient()
		configureNetBoxInterfaces(api, netboxInterfaceForTest("501", "eno1", "AA:BB:CC:DD:EE:01",
			map[string]interface{}{"osac_logical_port": "data-0"}))

		macs, err := client.GetHostLogicalPortMACs(context.Background(), "baremetal/netbox-42")

		Expect(err).NotTo(HaveOccurred())
		Expect(macs).To(Equal(map[string]string{"data-0": "aa:bb:cc:dd:ee:01"}))
		Expect(macs).NotTo(HaveKey("eno1"))
	})

	DescribeTable("LOG-03 falls back to the native name for absent or empty aliases",
		func(customFields map[string]interface{}) {
			client, api := newNetBoxLogicalMACTestClient()
			configureNetBoxInterfaces(api, netboxInterfaceForTest("501", "data-0", "AA:BB:CC:DD:EE:01", customFields))

			macs, err := client.GetHostLogicalPortMACs(context.Background(), "baremetal/netbox-42")

			Expect(err).NotTo(HaveOccurred())
			Expect(macs).To(Equal(map[string]string{"data-0": "aa:bb:cc:dd:ee:01"}))
		},
		Entry("nil custom fields", nil),
		Entry("alias key absent", map[string]interface{}{"unrelated": "value"}),
		Entry("null alias", map[string]interface{}{"osac_logical_port": nil}),
		Entry("empty alias", map[string]interface{}{"osac_logical_port": ""}),
	)

	DescribeTable("LOG-04 preserves case in the logical name",
		func(name string, customFields map[string]interface{}) {
			client, api := newNetBoxLogicalMACTestClient()
			configureNetBoxInterfaces(api, netboxInterfaceForTest("501", name, "AA:BB:CC:DD:EE:01", customFields))

			macs, err := client.GetHostLogicalPortMACs(context.Background(), "baremetal/netbox-42")

			Expect(err).NotTo(HaveOccurred())
			Expect(macs).To(Equal(map[string]string{"Data-0": "aa:bb:cc:dd:ee:01"}))
		},
		Entry("native name", "Data-0", nil),
		Entry("alias", "eno1", map[string]interface{}{"osac_logical_port": "Data-0"}),
	)

	DescribeTable("LOG-05 normalizes six-octet MAC spellings",
		func(rawMAC string) {
			client, api := newNetBoxLogicalMACTestClient()
			configureNetBoxInterfaces(api, netboxInterfaceForTest("501", "data-0", rawMAC, nil))

			macs, err := client.GetHostLogicalPortMACs(context.Background(), "baremetal/netbox-42")

			Expect(err).NotTo(HaveOccurred())
			Expect(macs).To(Equal(map[string]string{"data-0": "aa:bb:cc:dd:ee:01"}))
		},
		Entry("uppercase colon-separated", "AA:BB:CC:DD:EE:01"),
		Entry("hyphen-separated", "AA-BB-CC-DD-EE-01"),
		Entry("Cisco dotted", "aabb.ccdd.ee01"),
	)

	DescribeTable("LOG-06 skips missing primary MAC values",
		func(interfaces []netboxclient.DeviceInterface, want map[string]string) {
			client, api := newNetBoxLogicalMACTestClient()
			configureNetBoxInterfaces(api, interfaces...)

			macs, err := client.GetHostLogicalPortMACs(context.Background(), "baremetal/netbox-42")

			Expect(err).NotTo(HaveOccurred())
			Expect(macs).NotTo(BeNil())
			Expect(macs).To(Equal(want))
		},
		Entry("one interface has no primary MAC", []netboxclient.DeviceInterface{
			netboxInterfaceForTest("501", "data-0", "AA:BB:CC:DD:EE:01", nil),
			netboxInterfaceForTest("502", "data-1", "", nil),
		}, map[string]string{"data-0": "aa:bb:cc:dd:ee:01"}),
		Entry("all interfaces have no primary MAC", []netboxclient.DeviceInterface{
			netboxInterfaceForTest("501", "data-0", "", nil),
		}, map[string]string{}),
	)

	DescribeTable("LOG-07 rejects malformed populated MACs atomically",
		func(rawMAC string) {
			client, api := newNetBoxLogicalMACTestClient()
			configureNetBoxInterfaces(api,
				netboxInterfaceForTest("501", "data-0", "AA:BB:CC:DD:EE:01", nil),
				netboxInterfaceForTest("502", "data-1", rawMAC, nil),
			)

			macs, err := client.GetHostLogicalPortMACs(context.Background(), "baremetal/netbox-42")

			Expect(err).To(HaveOccurred())
			Expect(macs).To(BeNil())
		},
		Entry("garbage", "not-a-mac"),
		Entry("whitespace-padded", " AA:BB:CC:DD:EE:01 "),
		Entry("EUI-64", "00:11:22:33:44:55:66:77"),
		Entry("20-byte link address", "00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33"),
	)

	DescribeTable("LOG-08 rejects populated aliases that are not strings",
		func(alias interface{}) {
			client, api := newNetBoxLogicalMACTestClient()
			configureNetBoxInterfaces(api, netboxInterfaceForTest("501", "data-0", "AA:BB:CC:DD:EE:01",
				map[string]interface{}{"osac_logical_port": alias}))

			macs, err := client.GetHostLogicalPortMACs(context.Background(), "baremetal/netbox-42")

			Expect(err).To(HaveOccurred())
			Expect(macs).To(BeNil())
		},
		Entry("number", 7),
		Entry("boolean", true),
		Entry("array", []interface{}{"data-0"}),
		Entry("object", map[string]interface{}{"name": "data-0"}),
	)

	DescribeTable("LOG-09 rejects whitespace-only or padded aliases",
		func(alias string) {
			client, api := newNetBoxLogicalMACTestClient()
			configureNetBoxInterfaces(api, netboxInterfaceForTest("501", "data-0", "AA:BB:CC:DD:EE:01",
				map[string]interface{}{"osac_logical_port": alias}))

			macs, err := client.GetHostLogicalPortMACs(context.Background(), "baremetal/netbox-42")

			Expect(err).To(HaveOccurred())
			Expect(macs).To(BeNil())
		},
		Entry("spaces only", "   "),
		Entry("leading space", " data-0"),
		Entry("trailing space", "data-0 "),
	)

	DescribeTable("LOG-10 rejects invalid native fallback names",
		func(name string) {
			client, api := newNetBoxLogicalMACTestClient()
			configureNetBoxInterfaces(api, netboxInterfaceForTest("501", name, "AA:BB:CC:DD:EE:01", nil))

			macs, err := client.GetHostLogicalPortMACs(context.Background(), "baremetal/netbox-42")

			Expect(err).To(HaveOccurred())
			Expect(macs).To(BeNil())
		},
		Entry("empty name", ""),
		Entry("whitespace-only name", "   "),
		Entry("leading space", " data-0"),
		Entry("trailing space", "data-0 "),
	)

	It("LOG-11 accepts a valid alias when the native name is empty", func() {
		client, api := newNetBoxLogicalMACTestClient()
		configureNetBoxInterfaces(api, netboxInterfaceForTest("501", "", "AA:BB:CC:DD:EE:01",
			map[string]interface{}{"osac_logical_port": "data-0"}))

		macs, err := client.GetHostLogicalPortMACs(context.Background(), "baremetal/netbox-42")

		Expect(err).NotTo(HaveOccurred())
		Expect(macs).To(Equal(map[string]string{"data-0": "aa:bb:cc:dd:ee:01"}))
	})

	It("LOG-12 rejects duplicate aliases with different MACs", func() {
		client, api := newNetBoxLogicalMACTestClient()
		configureNetBoxInterfaces(api,
			netboxInterfaceForTest("501", "eno1", "AA:BB:CC:DD:EE:01", map[string]interface{}{"osac_logical_port": "sensitive-logical-alias-5953"}),
			netboxInterfaceForTest("502", "eno2", "AA:BB:CC:DD:EE:02", map[string]interface{}{"osac_logical_port": "sensitive-logical-alias-5953"}),
		)

		macs, err := client.GetHostLogicalPortMACs(context.Background(), "baremetal/netbox-42")

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("501"))
		Expect(err.Error()).To(ContainSubstring("502"))
		Expect(err.Error()).NotTo(ContainSubstring("sensitive-logical-alias-5953"))
		Expect(macs).To(BeNil())
	})

	It("LOG-13 rejects duplicate logical names even with equal MACs", func() {
		client, api := newNetBoxLogicalMACTestClient()
		configureNetBoxInterfaces(api,
			netboxInterfaceForTest("501", "data-0", "AA:BB:CC:DD:EE:01", nil),
			netboxInterfaceForTest("502", "data-0", "AA:BB:CC:DD:EE:01", nil),
		)

		macs, err := client.GetHostLogicalPortMACs(context.Background(), "baremetal/netbox-42")

		Expect(err).To(HaveOccurred())
		Expect(macs).To(BeNil())
	})

	DescribeTable("LOG-14 rejects alias versus native-name collisions in both orders",
		func(nativeFirst bool) {
			client, api := newNetBoxLogicalMACTestClient()
			alias := netboxInterfaceForTest("501", "eno1", "AA:BB:CC:DD:EE:01",
				map[string]interface{}{"osac_logical_port": "data-0"})
			native := netboxInterfaceForTest("502", "data-0", "AA:BB:CC:DD:EE:02", nil)
			if nativeFirst {
				configureNetBoxInterfaces(api, native, alias)
			} else {
				configureNetBoxInterfaces(api, alias, native)
			}

			macs, err := client.GetHostLogicalPortMACs(context.Background(), "baremetal/netbox-42")

			Expect(err).To(HaveOccurred())
			Expect(macs).To(BeNil())
		},
		Entry("alias first", false),
		Entry("native name first", true),
	)

	DescribeTable("LOG-15 reserves names before checking primary MAC data",
		func(noMACFirst bool) {
			client, api := newNetBoxLogicalMACTestClient()
			withMAC := netboxInterfaceForTest("501", "data-0", "AA:BB:CC:DD:EE:01", nil)
			withoutMAC := netboxInterfaceForTest("502", "data-0", "", nil)
			if noMACFirst {
				configureNetBoxInterfaces(api, withoutMAC, withMAC)
			} else {
				configureNetBoxInterfaces(api, withMAC, withoutMAC)
			}

			macs, err := client.GetHostLogicalPortMACs(context.Background(), "baremetal/netbox-42")

			Expect(err).To(HaveOccurred())
			Expect(macs).To(BeNil())
		},
		Entry("MAC present first", false),
		Entry("missing MAC first", true),
	)

	It("LOG-16 rejects a repeated record delivered on another page", func() {
		client, api := newNetBoxLogicalMACTestClient()
		iface := netboxInterfaceForTest("501", "data-0", "AA:BB:CC:DD:EE:01", nil)
		configureNetBoxInterfaces(api, iface, iface)

		macs, err := client.GetHostLogicalPortMACs(context.Background(), "baremetal/netbox-42")

		Expect(err).To(HaveOccurred())
		Expect(macs).To(BeNil())
	})

	It("LOG-17 allows distinct logical names to share a MAC", func() {
		client, api := newNetBoxLogicalMACTestClient()
		configureNetBoxInterfaces(api,
			netboxInterfaceForTest("501", "data-0", "AA:BB:CC:DD:EE:01", nil),
			netboxInterfaceForTest("502", "data-1", "AA:BB:CC:DD:EE:01", nil),
		)

		macs, err := client.GetHostLogicalPortMACs(context.Background(), "baremetal/netbox-42")

		Expect(err).NotTo(HaveOccurred())
		Expect(macs).To(Equal(map[string]string{
			"data-0": "aa:bb:cc:dd:ee:01",
			"data-1": "aa:bb:cc:dd:ee:01",
		}))
	})

	It("LOG-18 ignores unrelated custom fields", func() {
		client, api := newNetBoxLogicalMACTestClient()
		configureNetBoxInterfaces(api, netboxInterfaceForTest("501", "data-0", "AA:BB:CC:DD:EE:01",
			map[string]interface{}{"unrelated": []interface{}{true, 3, "opaque"}}))

		macs, err := client.GetHostLogicalPortMACs(context.Background(), "baremetal/netbox-42")

		Expect(err).NotTo(HaveOccurred())
		Expect(macs).To(Equal(map[string]string{"data-0": "aa:bb:cc:dd:ee:01"}))
	})

	It("LOG-19 returns a fresh empty map for zero interfaces", func() {
		client, api := newNetBoxLogicalMACTestClient()
		configureNetBoxInterfaces(api)

		macs, err := client.GetHostLogicalPortMACs(context.Background(), "baremetal/netbox-42")

		Expect(err).NotTo(HaveOccurred())
		Expect(macs).NotTo(BeNil())
		Expect(macs).To(BeEmpty())
	})

	It("LOG-20 discards partial results when interface listing fails", func() {
		client, api := newNetBoxLogicalMACTestClient()
		sentinel := errors.New("later interface page failed")
		api.interfaceList = func(_ context.Context, _ string, visit func(netboxclient.DeviceInterface) (bool, error)) error {
			iface := netboxInterfaceForTest("501", "data-0", "AA:BB:CC:DD:EE:01", nil)
			if _, err := visit(iface); err != nil {
				return err
			}
			return sentinel
		}

		macs, err := client.GetHostLogicalPortMACs(context.Background(), "baremetal/netbox-42")

		Expect(errors.Is(err, sentinel)).To(BeTrue())
		Expect(macs).To(BeNil())
	})

	DescribeTable("LOG-21 preserves typed NetBox API failures",
		func(apiFailure *netboxclient.APIError) {
			client, api := newNetBoxLogicalMACTestClient()
			api.interfaceList = func(context.Context, string, func(netboxclient.DeviceInterface) (bool, error)) error {
				return apiFailure
			}

			macs, err := client.GetHostLogicalPortMACs(context.Background(), "baremetal/netbox-42")

			Expect(macs).To(BeNil())
			var got *netboxclient.APIError
			Expect(errors.As(err, &got)).To(BeTrue())
			Expect(got).To(BeIdenticalTo(apiFailure))
		},
		Entry("forbidden", &netboxclient.APIError{Kind: netboxclient.ErrorKindForbidden, StatusCode: 403}),
		Entry("not found", &netboxclient.APIError{Kind: netboxclient.ErrorKindNotFound, StatusCode: 404}),
		Entry("invalid response", &netboxclient.APIError{Kind: netboxclient.ErrorKindInvalidResponse}),
	)

	It("LOG-22 queries once with the saved NetBox device ID and caller context", func() {
		client, api := newNetBoxLogicalMACTestClient()
		ctx := context.WithValue(context.Background(), netBoxNICContextKey{}, "caller-context")
		var requestedContext context.Context
		var requestedID string
		api.interfaceList = func(gotContext context.Context, deviceID string, visit func(netboxclient.DeviceInterface) (bool, error)) error {
			requestedContext = gotContext
			requestedID = deviceID
			iface := netboxInterfaceForTest("501", "data-0", "AA:BB:CC:DD:EE:01", nil)
			_, err := visit(iface)
			return err
		}

		macs, err := client.GetHostLogicalPortMACs(ctx, "baremetal/netbox-42")

		Expect(err).NotTo(HaveOccurred())
		Expect(macs).To(Equal(map[string]string{"data-0": "aa:bb:cc:dd:ee:01"}))
		Expect(requestedContext).To(BeIdenticalTo(ctx))
		Expect(requestedID).To(Equal("42"))
		Expect(api.calls).To(Equal(1))
	})

	It("LOG-23 does not read or compare inspected NICs", func() {
		client, api := newNetBoxLogicalMACTestClient()
		configureNetBoxInterfaces(api, netboxInterfaceForTest("501", "data-0", "52:54:00:16:04:83", nil))

		macs, err := client.GetHostLogicalPortMACs(context.Background(), "baremetal/netbox-42")

		Expect(err).NotTo(HaveOccurred())
		Expect(macs).To(Equal(map[string]string{"data-0": "52:54:00:16:04:83"}))
	})

	It("LOG-24 uses native interface data without reading a device JSON map", func() {
		client, api := newNetBoxLogicalMACTestClient()
		configureNetBoxInterfaces(api, netboxInterfaceForTest("501", "data-0", "AA:BB:CC:DD:EE:01", nil))

		macs, err := client.GetHostLogicalPortMACs(context.Background(), "baremetal/netbox-42")

		Expect(err).NotTo(HaveOccurred())
		Expect(macs).To(Equal(map[string]string{"data-0": "aa:bb:cc:dd:ee:01"}))
		Expect(api.calls).To(Equal(1))
	})

	It("LOG-25 reads fresh data on every invocation", func() {
		client, api := newNetBoxLogicalMACTestClient()
		api.interfaceList = func(_ context.Context, _ string, visit func(netboxclient.DeviceInterface) (bool, error)) error {
			mac := "AA:BB:CC:DD:EE:01"
			if api.calls == 2 {
				mac = "52:54:00:16:04:83"
			}
			iface := netboxInterfaceForTest("501", "data-0", mac, nil)
			_, err := visit(iface)
			return err
		}

		first, err := client.GetHostLogicalPortMACs(context.Background(), "baremetal/netbox-42")
		Expect(err).NotTo(HaveOccurred())
		first["data-0"] = "modified"

		second, err := client.GetHostLogicalPortMACs(context.Background(), "baremetal/netbox-42")

		Expect(err).NotTo(HaveOccurred())
		Expect(first["data-0"]).To(Equal("modified"))
		Expect(second).To(Equal(map[string]string{"data-0": "52:54:00:16:04:83"}))
		Expect(api.calls).To(Equal(2))
	})

	It("LOG-26 does not infer a logical name from an unmatched native interface", func() {
		client, api := newNetBoxLogicalMACTestClient()
		configureNetBoxInterfaces(api, netboxInterfaceForTest("501", "eno1", "AA:BB:CC:DD:EE:01", nil))

		macs, err := client.GetHostLogicalPortMACs(context.Background(), "baremetal/netbox-42")

		Expect(err).NotTo(HaveOccurred())
		Expect(macs).To(Equal(map[string]string{"eno1": "aa:bb:cc:dd:ee:01"}))
		Expect(macs).NotTo(HaveKey("data-0"))
	})

	It("LOG-27 rejects a malformed alias instead of falling back to the native name", func() {
		client, api := newNetBoxLogicalMACTestClient()
		configureNetBoxInterfaces(api, netboxInterfaceForTest("501", "data-0", "AA:BB:CC:DD:EE:01",
			map[string]interface{}{"osac_logical_port": " data-0"}))

		macs, err := client.GetHostLogicalPortMACs(context.Background(), "baremetal/netbox-42")

		Expect(err).To(HaveOccurred())
		Expect(macs).To(BeNil())
	})

	DescribeTable("LOG-28 discards valid mappings around an unrelated invalid interface",
		func(invalid netboxclient.DeviceInterface, invalidFirst bool) {
			client, api := newNetBoxLogicalMACTestClient()
			valid := netboxInterfaceForTest("501", "data-0", "AA:BB:CC:DD:EE:01", nil)
			if invalidFirst {
				configureNetBoxInterfaces(api, invalid, valid)
			} else {
				configureNetBoxInterfaces(api, valid, invalid)
			}

			macs, err := client.GetHostLogicalPortMACs(context.Background(), "baremetal/netbox-42")

			Expect(err).To(HaveOccurred())
			Expect(macs).To(BeNil())
		},
		Entry("invalid alias after valid record", netboxInterfaceForTest("502", "eno2", "AA:BB:CC:DD:EE:02",
			map[string]interface{}{"osac_logical_port": "data-1 "}), false),
		Entry("invalid alias before valid record", netboxInterfaceForTest("502", "eno2", "AA:BB:CC:DD:EE:02",
			map[string]interface{}{"osac_logical_port": "data-1 "}), true),
		Entry("invalid MAC after valid record", netboxInterfaceForTest("502", "data-1", "bad-mac", nil), false),
		Entry("invalid MAC before valid record", netboxInterfaceForTest("502", "data-1", "bad-mac", nil), true),
	)

	It("LOG-29 returns cancellation and discards results when cancellation occurs during iteration", func() {
		client, api := newNetBoxLogicalMACTestClient()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		var accepted []string
		api.interfaceList = func(_ context.Context, _ string, visit func(netboxclient.DeviceInterface) (bool, error)) error {
			first := netboxInterfaceForTest("501", "data-0", "AA:BB:CC:DD:EE:01", nil)
			keepGoing, err := visit(first)
			if err != nil || !keepGoing {
				return err
			}
			accepted = append(accepted, first.ID)
			cancel()
			second := netboxInterfaceForTest("502", "data-1", "AA:BB:CC:DD:EE:02", nil)
			_, err = visit(second)
			if err == nil {
				accepted = append(accepted, second.ID)
			}
			return err
		}

		macs, err := client.GetHostLogicalPortMACs(ctx, "baremetal/netbox-42")

		Expect(errors.Is(err, context.Canceled)).To(BeTrue())
		Expect(macs).To(BeNil())
		Expect(accepted).To(Equal([]string{"501"}))
	})

	It("LOG-30 discards the result when the interface walker returns success after cancellation", func() {
		client, api := newNetBoxLogicalMACTestClient()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		api.interfaceList = func(_ context.Context, _ string, visit func(netboxclient.DeviceInterface) (bool, error)) error {
			iface := netboxInterfaceForTest("501", "data-0", "AA:BB:CC:DD:EE:01", nil)
			keepGoing, err := visit(iface)
			Expect(err).NotTo(HaveOccurred())
			Expect(keepGoing).To(BeTrue())
			cancel()
			return nil
		}

		macs, err := client.GetHostLogicalPortMACs(ctx, "baremetal/netbox-42")

		Expect(errors.Is(err, context.Canceled)).To(BeTrue())
		Expect(macs).To(BeNil())
	})
})

type nicReadTestAPI struct {
	calls         int
	interfaceList func(context.Context, string, func(netboxclient.DeviceInterface) (bool, error)) error
}

var _ NetBoxAPI = (*nicReadTestAPI)(nil)

func (a *nicReadTestAPI) unexpected(operation string) error {
	a.calls++
	Fail("unexpected NetBox API operation: " + operation)
	return fmt.Errorf("unexpected NetBox API operation: %s", operation)
}

func (a *nicReadTestAPI) ForEachDevice(
	context.Context,
	netboxclient.DeviceQuery,
	func(netboxclient.Device) (bool, error),
) error {
	return a.unexpected("ForEachDevice")
}

func (a *nicReadTestAPI) ForEachDeviceInterface(
	ctx context.Context,
	deviceID string,
	visit func(netboxclient.DeviceInterface) (bool, error),
) error {
	a.calls++
	if a.interfaceList == nil {
		Fail("unexpected NetBox API operation: ForEachDeviceInterface")
		return errors.New("unexpected NetBox API operation: ForEachDeviceInterface")
	}
	return a.interfaceList(ctx, deviceID, visit)
}

func (a *nicReadTestAPI) ForEachDeviceCustomField(
	context.Context,
	func(netboxclient.CustomField) (bool, error),
) error {
	return a.unexpected("ForEachDeviceCustomField")
}

func (a *nicReadTestAPI) GetDevice(context.Context, string) (netboxclient.DeviceSnapshot, error) {
	return netboxclient.DeviceSnapshot{}, a.unexpected("GetDevice")
}

func (a *nicReadTestAPI) PatchDevice(
	context.Context,
	string,
	netboxclient.DevicePatch,
	string,
) (netboxclient.DeviceSnapshot, error) {
	return netboxclient.DeviceSnapshot{}, a.unexpected("PatchDevice")
}

type netBoxNICContextKey struct{}

func newNetBoxLogicalMACTestClient() (*NetBoxClient, *nicReadTestAPI) {
	manager := baremetalhost.NewMockBMHLifecycleManager(gomock.NewController(GinkgoT()))
	manager.EXPECT().Namespace().AnyTimes().Return("baremetal")
	manager.EXPECT().GetHardwareNICs(gomock.Any(), gomock.Any()).Times(0)
	api := &nicReadTestAPI{}
	return NewNetBoxClient(api, manager, testNetBoxHostClass), api
}

func configureNetBoxInterfaces(api *nicReadTestAPI, interfaces ...netboxclient.DeviceInterface) {
	api.interfaceList = func(_ context.Context, _ string, visit func(netboxclient.DeviceInterface) (bool, error)) error {
		for _, iface := range interfaces {
			keepGoing, err := visit(iface)
			if err != nil {
				return err
			}
			if !keepGoing {
				return nil
			}
		}
		return nil
	}
}

func netboxInterfaceForTest(id, name, primaryMAC string, customFields map[string]interface{}) netboxclient.DeviceInterface {
	return netboxclient.DeviceInterface{
		ID: id, Name: name, PrimaryMAC: primaryMAC, CustomFields: customFields,
	}
}
