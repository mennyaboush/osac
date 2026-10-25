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
		func(inventoryHostID, bmhName string) {
			ctx := context.Background()
			manager := baremetalhost.NewMockBMHLifecycleManager(gomock.NewController(GinkgoT()))
			manager.EXPECT().Namespace().Return("baremetal")
			manager.EXPECT().GetHardwareNICs(gomock.Eq(ctx), bmhName).
				Return([]string{"AA:BB:CC:DD:EE:01"}, nil)
			api := &nicReadTestAPI{}

			nics, err := NewNetBoxClient(api, manager, netBoxHostClass).GetHostNICs(ctx, inventoryHostID)

			Expect(err).NotTo(HaveOccurred())
			Expect(nics).To(Equal([]HostNIC{{MAC: "aa:bb:cc:dd:ee:01"}}))
			Expect(api.calls).To(BeZero())
		},
		Entry("netbox ID 1", "baremetal/netbox-1", "netbox-1"),
		Entry("netbox ID 42", "baremetal/netbox-42", "netbox-42"),
		Entry("maximum int32 ID", "baremetal/netbox-2147483647", "netbox-2147483647"),
	)

	DescribeTable("ID-02 through ID-05 reject malformed saved host IDs before dependency I/O",
		func(inventoryHostID string) {
			manager := baremetalhost.NewMockBMHLifecycleManager(gomock.NewController(GinkgoT()))
			manager.EXPECT().Namespace().AnyTimes().Return("baremetal")
			api := &nicReadTestAPI{}

			nics, err := NewNetBoxClient(api, manager, netBoxHostClass).
				GetHostNICs(context.Background(), inventoryHostID)

			Expect(err).To(HaveOccurred())
			Expect(errors.Is(err, errNetBoxClientNotImplemented)).To(BeFalse())
			Expect(nics).To(BeNil())
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

		nics, err := client.GetHostNICs(context.Background(), "baremetal/netbox-42")

		Expect(err).To(HaveOccurred())
		Expect(errors.Is(err, errNetBoxClientNotImplemented)).To(BeFalse())
		Expect(nics).To(BeNil())
	})

	It("ID-06 rejects a zero-value client", func() {
		nics, err := (&NetBoxClient{}).GetHostNICs(context.Background(), "baremetal/netbox-42")

		Expect(err).To(HaveOccurred())
		Expect(errors.Is(err, errNetBoxClientNotImplemented)).To(BeFalse())
		Expect(nics).To(BeNil())
	})

	It("ID-06 rejects a missing manager", func() {
		api := &nicReadTestAPI{}
		client := NewNetBoxClient(api, nil, netBoxHostClass)

		nics, err := client.GetHostNICs(context.Background(), "baremetal/netbox-42")

		Expect(err).To(HaveOccurred())
		Expect(errors.Is(err, errNetBoxClientNotImplemented)).To(BeFalse())
		Expect(nics).To(BeNil())
		Expect(api.calls).To(BeZero())
	})

	It("ID-06 rejects an empty configured namespace", func() {
		manager := baremetalhost.NewMockBMHLifecycleManager(gomock.NewController(GinkgoT()))
		manager.EXPECT().Namespace().Return("")
		api := &nicReadTestAPI{}
		client := NewNetBoxClient(api, manager, netBoxHostClass)

		nics, err := client.GetHostNICs(context.Background(), "baremetal/netbox-42")

		Expect(err).To(HaveOccurred())
		Expect(errors.Is(err, errNetBoxClientNotImplemented)).To(BeFalse())
		Expect(nics).To(BeNil())
		Expect(api.calls).To(BeZero())
	})

	It("ID-07 reads physical NICs without a NetBox API", func() {
		ctx := context.Background()
		manager := baremetalhost.NewMockBMHLifecycleManager(gomock.NewController(GinkgoT()))
		manager.EXPECT().Namespace().Return("baremetal")
		manager.EXPECT().GetHardwareNICs(gomock.Eq(ctx), "netbox-42").
			Return([]string{"AA:BB:CC:DD:EE:01"}, nil)

		nics, err := NewNetBoxClient(nil, manager, netBoxHostClass).
			GetHostNICs(ctx, "baremetal/netbox-42")

		Expect(err).NotTo(HaveOccurred())
		Expect(nics).To(Equal([]HostNIC{{MAC: "aa:bb:cc:dd:ee:01"}}))
	})

	It("ID-08 returns pre-cancelled context without reading dependencies", func() {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		manager := baremetalhost.NewMockBMHLifecycleManager(gomock.NewController(GinkgoT()))
		manager.EXPECT().Namespace().Return("baremetal")
		api := &nicReadTestAPI{}

		nics, err := NewNetBoxClient(api, manager, netBoxHostClass).
			GetHostNICs(ctx, "baremetal/netbox-42")

		Expect(errors.Is(err, context.Canceled)).To(BeTrue())
		Expect(nics).To(BeNil())
		Expect(api.calls).To(BeZero())
	})

	It("PHY-01 preserves manager order and lowercases physical MACs", func() {
		ctx := context.Background()
		manager := baremetalhost.NewMockBMHLifecycleManager(gomock.NewController(GinkgoT()))
		manager.EXPECT().Namespace().Return("baremetal")
		manager.EXPECT().GetHardwareNICs(gomock.Eq(ctx), "netbox-42").
			Return([]string{"AA:BB:CC:DD:EE:01", "52:54:00:16:04:83"}, nil)
		api := &nicReadTestAPI{}

		nics, err := NewNetBoxClient(api, manager, netBoxHostClass).
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

			nics, err := NewNetBoxClient(nil, manager, netBoxHostClass).
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

		nics, err := NewNetBoxClient(nil, manager, netBoxHostClass).
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

		nics, err := NewNetBoxClient(nil, manager, netBoxHostClass).
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

		nics, err := NewNetBoxClient(nil, manager, netBoxHostClass).
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

		_, err := NewNetBoxClient(api, manager, netBoxHostClass).
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

		nics, err := NewNetBoxClient(nil, manager, netBoxHostClass).
			GetHostNICs(ctx, "baremetal/netbox-42")

		Expect(err).NotTo(HaveOccurred())
		Expect(nics).To(Equal([]HostNIC{{MAC: "opaque-mac value"}}))
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
