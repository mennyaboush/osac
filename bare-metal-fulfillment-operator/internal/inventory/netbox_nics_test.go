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

	. "github.com/onsi/ginkgo/v2" //nolint:revive,staticcheck
	. "github.com/onsi/gomega"    //nolint:revive,staticcheck
	"go.uber.org/mock/gomock"

	"github.com/osac-project/osac/bare-metal-fulfillment-operator/internal/baremetalhost"
	"github.com/osac-project/osac/bare-metal-fulfillment-operator/internal/netboxclient"
)

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
