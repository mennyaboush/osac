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
	"strings"

	. "github.com/onsi/ginkgo/v2" //nolint:revive,staticcheck
	. "github.com/onsi/gomega"    //nolint:revive,staticcheck

	"github.com/osac-project/osac/bare-metal-fulfillment-operator/internal/baremetalhost"
	"github.com/osac-project/osac/bare-metal-fulfillment-operator/internal/netboxclient"
	"github.com/osac-project/osac/bare-metal-fulfillment-operator/internal/shared"
)

type schemaValidationTestAPI struct {
	fields        []netboxclient.CustomField
	schemaErr     error
	schemaReads   int
	deviceQueries int
	deviceQuery   netboxclient.DeviceQuery
	devices       []netboxclient.Device
	deviceErr     error
	deviceVisits  int
}

func (a *schemaValidationTestAPI) ForEachDevice(
	_ context.Context,
	query netboxclient.DeviceQuery,
	visit func(netboxclient.Device) (bool, error),
) error {
	a.deviceQueries++
	a.deviceQuery = make(netboxclient.DeviceQuery, len(query))
	for key, value := range query {
		a.deviceQuery[key] = value
	}
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

func (a *schemaValidationTestAPI) ForEachDeviceCustomField(
	_ context.Context,
	visit func(netboxclient.CustomField) (bool, error),
) error {
	a.schemaReads++
	if a.schemaErr != nil {
		return a.schemaErr
	}

	for _, field := range a.fields {
		keepGoing, err := visit(field)
		if err != nil {
			return err
		}
		if !keepGoing {
			return nil
		}
	}
	return nil
}

func (*schemaValidationTestAPI) GetDevice(context.Context, string) (netboxclient.DeviceSnapshot, error) {
	return netboxclient.DeviceSnapshot{}, nil
}

func (*schemaValidationTestAPI) PatchDevice(
	context.Context,
	string,
	netboxclient.DevicePatch,
	string,
) (netboxclient.DeviceSnapshot, error) {
	return netboxclient.DeviceSnapshot{}, nil
}

var _ = Describe("NetBox schema validation", func() {
	Describe("ValidateFixedSchema", func() {
		DescribeTable("accepts valid fixed-field schemas",
			func(activeStatus, unsetDefaults bool) {
				fields := fixedSchemaTestFields()
				if activeStatus {
					for i := range fields {
						fields[i].Status = stringPointer("active")
					}
				}
				if unsetDefaults {
					fields[0].Default = nil
					fields[1].Default = nil
				}
				client := NewNetBoxClient(&schemaValidationTestAPI{fields: fields}, nil, netBoxHostClass)

				Expect(client.ValidateFixedSchema(context.Background())).To(Succeed())
			},
			Entry("status omitted", false, false),
			Entry("active status", true, false),
			Entry("optional defaults omitted", false, true),
		)

		It("returns custom-field discovery errors", func() {
			apiError := errors.New("schema endpoint unavailable")
			client := NewNetBoxClient(&schemaValidationTestAPI{schemaErr: apiError}, nil, netBoxHostClass)

			err := client.ValidateFixedSchema(context.Background())

			Expect(err).To(MatchError(ContainSubstring("failed to discover NetBox device custom-field schema")))
			Expect(errors.Is(err, apiError)).To(BeTrue())
		})

		DescribeTable("rejects incompatible fixed-field schemas",
			func(mutate func([]netboxclient.CustomField) []netboxclient.CustomField, want string) {
				fields := mutate(fixedSchemaTestFields())
				client := NewNetBoxClient(&schemaValidationTestAPI{fields: fields}, nil, netBoxHostClass)

				err := client.ValidateFixedSchema(context.Background())

				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring(want))
			},
			Entry("missing field", func(fields []netboxclient.CustomField) []netboxclient.CustomField {
				return fields[1:]
			}, "osac_managed"),
			Entry("ambiguous field", func(fields []netboxclient.CustomField) []netboxclient.CustomField {
				return append(fields, fields[1])
			}, "ambiguous"),
			Entry("wrong object type", func(fields []netboxclient.CustomField) []netboxclient.CustomField {
				fields[0].ObjectTypes = []string{"virtualization.virtualmachine"}
				return fields
			}, "osac_managed"),
			Entry("wrong field type", func(fields []netboxclient.CustomField) []netboxclient.CustomField {
				fields[0].Type = "text"
				return fields
			}, "osac_managed"),
			Entry("required managed field", func(fields []netboxclient.CustomField) []netboxclient.CustomField {
				fields[0].Required = true
				return fields
			}, "osac_managed"),
			Entry("required owner field", func(fields []netboxclient.CustomField) []netboxclient.CustomField {
				fields[1].Required = true
				return fields
			}, "osac_instance_id"),
			Entry("unsafe managed default", func(fields []netboxclient.CustomField) []netboxclient.CustomField {
				fields[0].Default = true
				return fields
			}, "osac_managed"),
			Entry("wrong managed default type", func(fields []netboxclient.CustomField) []netboxclient.CustomField {
				fields[0].Default = "false"
				return fields
			}, "osac_managed"),
			Entry("disabled managed filter", func(fields []netboxclient.CustomField) []netboxclient.CustomField {
				fields[0].FilterLogic = "disabled"
				return fields
			}, "osac_managed"),
			Entry("loose owner filter", func(fields []netboxclient.CustomField) []netboxclient.CustomField {
				fields[1].FilterLogic = "loose"
				return fields
			}, "osac_instance_id"),
			Entry("nonempty owner default", func(fields []netboxclient.CustomField) []netboxclient.CustomField {
				fields[1].Default = "claimed"
				return fields
			}, "osac_instance_id"),
			Entry("wrong owner default type", func(fields []netboxclient.CustomField) []netboxclient.CustomField {
				fields[1].Default = false
				return fields
			}, "osac_instance_id"),
			Entry("wrong BMC field type", func(fields []netboxclient.CustomField) []netboxclient.CustomField {
				fields[2].Type = "integer"
				return fields
			}, "osac_bmc_address"),
			Entry("inactive fixed field", func(fields []netboxclient.CustomField) []netboxclient.CustomField {
				fields[3].Status = stringPointer("deleting")
				return fields
			}, "osac_boot_mac"),
		)
	})

	Describe("FindFreeHost", func() {
		It("queries NetBox directly without fetching custom-field metadata", func() {
			api := &schemaValidationTestAPI{
				schemaErr: errors.New("custom-field metadata should not be fetched"),
				devices:   []netboxclient.Device{{ID: "46"}},
			}
			client := NewNetBoxClient(api, testNetBoxBMHManager(), netBoxHostClass)
			selector := map[string]string{"cpu_cores": "016", "placement_zone": " Lab A "}

			host, err := client.FindFreeHost(context.Background(), selector)

			Expect(err).NotTo(HaveOccurred())
			Expect(host).To(Equal(&Host{
				InventoryHostID: "metal3-system/netbox-46",
				Name:            "netbox-46",
				HostClass:       netBoxHostClass,
				ProvisionState:  shared.OsacDefaultProvisionStateValue,
				ManagedBy:       shared.OsacDefaultManagedByValue,
				Ready:           true,
			}))
			Expect(api.schemaReads).To(BeZero())
			Expect(api.deviceQueries).To(Equal(1))
			Expect(api.deviceQuery).To(Equal(netboxclient.DeviceQuery{
				"status":                     "staged",
				"cf_osac_managed":            "true",
				"cf_osac_instance_id__empty": "true",
				"cf_cpu_cores":               "016",
				"cf_placement_zone":          " Lab A ",
			}))
		})

		It("returns device-list errors", func() {
			apiError := errors.New("device endpoint unavailable")
			api := &schemaValidationTestAPI{deviceErr: apiError}
			client := NewNetBoxClient(api, testNetBoxBMHManager(), netBoxHostClass)

			host, err := client.FindFreeHost(context.Background(), map[string]string{"placement_zone": "west"})

			Expect(host).To(BeNil())
			Expect(err).To(MatchError(ContainSubstring("failed to search NetBox for a free host")))
			Expect(errors.Is(err, apiError)).To(BeTrue())
			Expect(api.schemaReads).To(BeZero())
			Expect(api.deviceQueries).To(Equal(1))
		})

		It("queries the fixed free-host filters when the selector is empty", func() {
			api := &schemaValidationTestAPI{}
			client := NewNetBoxClient(api, testNetBoxBMHManager(), netBoxHostClass)

			host, err := client.FindFreeHost(context.Background(), nil)

			Expect(host).To(BeNil())
			Expect(err).NotTo(HaveOccurred())
			Expect(api.schemaReads).To(BeZero())
			Expect(api.deviceQueries).To(Equal(1))
			Expect(api.deviceQuery).To(Equal(netboxclient.DeviceQuery{
				"status":                     "staged",
				"cf_osac_managed":            "true",
				"cf_osac_instance_id__empty": "true",
			}))
		})

		It("returns the first device from NetBox and stops iteration", func() {
			api := &schemaValidationTestAPI{
				devices: []netboxclient.Device{
					{ID: "46", Name: "netbox-device-46"},
					{ID: "47", Name: "netbox-device-47"},
				},
			}
			client := NewNetBoxClient(api, testNetBoxBMHManager(), netBoxHostClass)
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
				HostClass:       netBoxHostClass,
				ProvisionState:  shared.OsacDefaultProvisionStateValue,
				ManagedBy:       shared.OsacDefaultManagedByValue,
				Ready:           true,
			}))
			Expect(api.schemaReads).To(BeZero())
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
	})

	Describe("Capability selector resolution", func() {
		DescribeTable("rejects reserved fields and lookup suffixes before querying NetBox",
			func(key string) {
				api := &schemaValidationTestAPI{}
				client := NewNetBoxClient(api, nil, netBoxHostClass)

				host, err := client.FindFreeHost(context.Background(), map[string]string{key: "value"})

				Expect(host).To(BeNil())
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).NotTo(ContainSubstring(key))
				Expect(err.Error()).NotTo(ContainSubstring("value"))
				Expect(api.schemaReads).To(BeZero())
				Expect(api.deviceQueries).To(BeZero())
			},
			Entry("managed integration field", "osac_managed"),
			Entry("owner integration field", "osac_instance_id"),
			Entry("BMC integration field", "osac_bmc_address"),
			Entry("boot MAC integration field", "osac_boot_mac"),
			Entry("lookup suffix", "gpu_model__ic"),
			Entry("numeric lookup suffix", "cpu_cores__gte"),
			Entry("arbitrary lookup suffix", "x__y"),
			Entry("owner lookup suffix", "osac_instance_id__empty"),
		)

		DescribeTable("preserves selector names in NetBox filter keys",
			func(key string) {
				filters, err := resolveCapabilitySelector(map[string]string{key: "a100"})

				Expect(err).NotTo(HaveOccurred())
				Expect(filters).To(Equal(netboxclient.DeviceQuery{"cf_" + key: "a100"}))
			},
			Entry("hyphenated name", "gpu-model"),
			Entry("name longer than 50 characters", strings.Repeat("x", 51)),
			Entry("name beginning with the query prefix", "cf_gpu_cores"),
		)

		DescribeTable("passes selector values unchanged to NetBox",
			func(value string) {
				filters, err := resolveCapabilitySelector(map[string]string{"capability": value})

				Expect(err).NotTo(HaveOccurred())
				Expect(filters).To(Equal(netboxclient.DeviceQuery{"cf_capability": value}))
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

		It("builds exact server-side filters for all selector fields", func() {
			selectorValues := map[string]string{
				"cpu_cores":      "9007199254740993",
				"accelerated":    "false",
				"Placement_Zone": "Lab A",
				"accelerator":    "a100",
			}

			filters, err := resolveCapabilitySelector(selectorValues)

			Expect(err).NotTo(HaveOccurred())
			Expect(filters).To(Equal(netboxclient.DeviceQuery{
				"cf_cpu_cores":      "9007199254740993",
				"cf_accelerated":    "false",
				"cf_Placement_Zone": "Lab A",
				"cf_accelerator":    "a100",
			}))
		})
	})

})

func testNetBoxBMHManager() *baremetalhost.Manager {
	return baremetalhost.NewManager(nil, nil, "metal3-system")
}

func fixedSchemaTestFields() []netboxclient.CustomField {
	return []netboxclient.CustomField{
		{
			Name: "osac_managed", Type: "boolean", Default: false,
			FilterLogic: "exact", ObjectTypes: []string{netBoxDeviceObjectType},
		},
		{
			Name: "osac_instance_id", Type: "text", Default: "",
			FilterLogic: "exact", ObjectTypes: []string{netBoxDeviceObjectType},
		},
		{Name: "osac_bmc_address", Type: "text", ObjectTypes: []string{netBoxDeviceObjectType}},
		{Name: "osac_boot_mac", Type: "text", ObjectTypes: []string{netBoxDeviceObjectType}},
	}
}

func stringPointer(value string) *string {
	return &value
}
