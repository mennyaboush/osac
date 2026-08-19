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

	. "github.com/onsi/ginkgo/v2" //nolint:revive,staticcheck
	. "github.com/onsi/gomega"    //nolint:revive,staticcheck
)

type mockDiscoverer struct {
	systemPath string
	err        error
	calledWith struct {
		bmcIP, bootMAC, username, password string
	}
}

func (m *mockDiscoverer) DiscoverSystemPath(_ context.Context, bmcIP, bootMAC, username, password string) (string, error) {
	m.calledWith.bmcIP = bmcIP
	m.calledWith.bootMAC = bootMAC
	m.calledWith.username = username
	m.calledWith.password = password
	return m.systemPath, m.err
}

var _ = Describe("classifyProtocol", func() {
	DescribeTable("should classify valid interface names",
		func(name string, expected Protocol) {
			protocol, err := classifyProtocol(name)
			Expect(err).NotTo(HaveOccurred())
			Expect(protocol).To(Equal(expected))
		},
		Entry("redfish rf0", "rf0", ProtocolRedfish),
		Entry("redfish rf1", "rf1", ProtocolRedfish),
		Entry("redfish rf12", "rf12", ProtocolRedfish),
		Entry("redfish rf99", "rf99", ProtocolRedfish),
		Entry("ipmi ipmi0", "ipmi0", ProtocolIPMI),
		Entry("ipmi ipmi1", "ipmi1", ProtocolIPMI),
		Entry("ilo ilo0", "ilo0", ProtocolILO),
		Entry("ilo ilo3", "ilo3", ProtocolILO),
		Entry("drac drac0", "drac0", ProtocolDRAC),
		Entry("drac drac1", "drac1", ProtocolDRAC),
	)

	DescribeTable("should be case-insensitive",
		func(name string, expected Protocol) {
			protocol, err := classifyProtocol(name)
			Expect(err).NotTo(HaveOccurred())
			Expect(protocol).To(Equal(expected))
		},
		Entry("uppercase RF0", "RF0", ProtocolRedfish),
		Entry("mixed case Ipmi0", "Ipmi0", ProtocolIPMI),
		Entry("uppercase ILO0", "ILO0", ProtocolILO),
		Entry("uppercase DRAC0", "DRAC0", ProtocolDRAC),
	)

	DescribeTable("should reject invalid names",
		func(name string) {
			_, err := classifyProtocol(name)
			Expect(err).To(HaveOccurred())
			Expect(errors.Is(err, ErrUnsupportedBMCType)).To(BeTrue())
			Expect(err.Error()).To(ContainSubstring(name))
		},
		Entry("unknown interface", "eth0"),
		Entry("empty string", ""),
		Entry("no numeric suffix", "rf"),
		Entry("no numeric suffix ipmi", "ipmi"),
		Entry("prefix only ilo", "ilo"),
		Entry("prefix only drac", "drac"),
		Entry("wrong prefix with number", "bmc0"),
		Entry("rf with text suffix", "rfx"),
		Entry("partial match", "redfishrf0"),
		Entry("spaces", "rf 0"),
	)
})

var _ = Describe("isRedfishCompatible", func() {
	DescribeTable("should return correct compatibility",
		func(protocol Protocol, expected bool) {
			Expect(isRedfishCompatible(protocol)).To(Equal(expected))
		},
		Entry("redfish is compatible", ProtocolRedfish, true),
		Entry("ilo is compatible", ProtocolILO, true),
		Entry("drac is compatible", ProtocolDRAC, true),
		Entry("ipmi is not compatible", ProtocolIPMI, false),
		Entry("unknown protocol is not compatible", Protocol("unknown"), false),
		Entry("empty protocol is not compatible", Protocol(""), false),
	)
})

var _ = Describe("ExtractBMCInfo", func() {
	const bmcChildType = "NetworkBmcInterface"

	It("should extract BMC info matching the given childType", func() {
		interfaces := []DeviceInterface{
			{ChildType: "NetworkPhysicalInterface", Name: "eth0", IP: "10.0.0.10"},
			{ChildType: bmcChildType, Name: "rf0", IP: "10.141.0.1"},
		}

		info, err := ExtractBMCInfo(interfaces, bmcChildType)
		Expect(err).NotTo(HaveOccurred())
		Expect(info.IP).To(Equal("10.141.0.1"))
		Expect(info.Protocol).To(Equal(ProtocolRedfish))
	})

	It("should use the first matching interface when multiple exist", func() {
		interfaces := []DeviceInterface{
			{ChildType: bmcChildType, Name: "rf0", IP: "10.141.0.1"},
			{ChildType: bmcChildType, Name: "ipmi0", IP: "10.141.0.2"},
		}

		info, err := ExtractBMCInfo(interfaces, bmcChildType)
		Expect(err).NotTo(HaveOccurred())
		Expect(info.IP).To(Equal("10.141.0.1"))
		Expect(info.Protocol).To(Equal(ProtocolRedfish))
	})

	It("should skip non-matching interface types", func() {
		interfaces := []DeviceInterface{
			{ChildType: "NetworkPhysicalInterface", Name: "eth0", IP: "10.0.0.10"},
			{ChildType: "NetworkVlanInterface", Name: "vlan100", IP: "10.0.1.10"},
			{ChildType: bmcChildType, Name: "ipmi0", IP: "10.141.0.5"},
		}

		info, err := ExtractBMCInfo(interfaces, bmcChildType)
		Expect(err).NotTo(HaveOccurred())
		Expect(info.IP).To(Equal("10.141.0.5"))
		Expect(info.Protocol).To(Equal(ProtocolIPMI))
	})

	It("should work with a custom childType", func() {
		interfaces := []DeviceInterface{
			{ChildType: "BmcPort", Name: "rf0", IP: "10.141.0.1"},
		}

		info, err := ExtractBMCInfo(interfaces, "BmcPort")
		Expect(err).NotTo(HaveOccurred())
		Expect(info.IP).To(Equal("10.141.0.1"))
		Expect(info.Protocol).To(Equal(ProtocolRedfish))
	})

	DescribeTable("should classify all protocol types",
		func(name string, expected Protocol) {
			interfaces := []DeviceInterface{
				{ChildType: bmcChildType, Name: name, IP: "10.141.0.1"},
			}
			info, err := ExtractBMCInfo(interfaces, bmcChildType)
			Expect(err).NotTo(HaveOccurred())
			Expect(info.Protocol).To(Equal(expected))
		},
		Entry("redfish", "rf0", ProtocolRedfish),
		Entry("ipmi", "ipmi0", ProtocolIPMI),
		Entry("ilo", "ilo0", ProtocolILO),
		Entry("drac", "drac0", ProtocolDRAC),
	)

	It("should return error when no matching interface exists", func() {
		interfaces := []DeviceInterface{
			{ChildType: "NetworkPhysicalInterface", Name: "eth0", IP: "10.0.0.10"},
		}

		_, err := ExtractBMCInfo(interfaces, bmcChildType)
		Expect(err).To(HaveOccurred())
		Expect(errors.Is(err, ErrNoBMCInterface)).To(BeTrue())
	})

	It("should return error for nil interfaces", func() {
		_, err := ExtractBMCInfo(nil, bmcChildType)
		Expect(err).To(HaveOccurred())
		Expect(errors.Is(err, ErrNoBMCInterface)).To(BeTrue())
	})

	It("should return error for empty interfaces", func() {
		_, err := ExtractBMCInfo([]DeviceInterface{}, bmcChildType)
		Expect(err).To(HaveOccurred())
		Expect(errors.Is(err, ErrNoBMCInterface)).To(BeTrue())
	})

	It("should return error for unsupported BMC type", func() {
		interfaces := []DeviceInterface{
			{ChildType: bmcChildType, Name: "unknown0", IP: "10.141.0.1"},
		}

		_, err := ExtractBMCInfo(interfaces, bmcChildType)
		Expect(err).To(HaveOccurred())
		Expect(errors.Is(err, ErrUnsupportedBMCType)).To(BeTrue())
	})
})

var _ = Describe("buildStaticAddress", func() {
	It("should build IPMI address", func() {
		Expect(buildStaticAddress("10.141.0.1")).To(Equal("ipmi://10.141.0.1"))
	})

	It("should wrap IPv6 in brackets", func() {
		Expect(buildStaticAddress("2001:db8::1")).To(Equal("ipmi://[2001:db8::1]"))
	})
})

var _ = Describe("buildRedfishAddress", func() {
	DescribeTable("should build correct addresses for all protocols",
		func(bmcIP string, protocol Protocol, systemPath string, expected string) {
			Expect(buildRedfishAddress(bmcIP, protocol, systemPath)).To(Equal(expected))
		},
		Entry("redfish simple path",
			"10.141.0.1", ProtocolRedfish, "/redfish/v1/Systems/1",
			"redfish-virtualmedia+https://10.141.0.1/redfish/v1/Systems/1"),
		Entry("idrac Dell path",
			"10.141.0.5", ProtocolDRAC, "/redfish/v1/Systems/System.Embedded.1",
			"idrac-virtualmedia+https://10.141.0.5/redfish/v1/Systems/System.Embedded.1"),
		Entry("ilo simple path",
			"10.141.0.9", ProtocolILO, "/redfish/v1/Systems/1",
			"ilo5-virtualmedia+https://10.141.0.9/redfish/v1/Systems/1"),
		Entry("redfish with complex path",
			"10.141.0.1", ProtocolRedfish, "/redfish/v1/Systems/437XR1138R2",
			"redfish-virtualmedia+https://10.141.0.1/redfish/v1/Systems/437XR1138R2"),
		Entry("redfish with IPv6",
			"2001:db8::1", ProtocolRedfish, "/redfish/v1/Systems/1",
			"redfish-virtualmedia+https://[2001:db8::1]/redfish/v1/Systems/1"),
	)
})

var _ = Describe("Resolve", func() {
	var ctx context.Context

	BeforeEach(func() {
		ctx = context.Background()
	})

	Context("IPMI (static URL, no Redfish discovery)", func() {
		It("should resolve without contacting BMC", func() {
			info := &BMCInfo{IP: "10.141.0.1", Protocol: ProtocolIPMI}

			address, err := Resolve(ctx, info, "aa:bb:cc:dd:ee:ff", "root", "pass", nil)
			Expect(err).NotTo(HaveOccurred())
			Expect(address).To(Equal("ipmi://10.141.0.1"))
		})

	})

	Context("Redfish-compatible protocols", func() {
		It("should resolve Redfish address via discoverer", func() {
			info := &BMCInfo{IP: "10.141.0.1", Protocol: ProtocolRedfish}
			disc := &mockDiscoverer{systemPath: "/redfish/v1/Systems/1"}

			address, err := Resolve(ctx, info, "aa:bb:cc:dd:ee:ff", "root", "pass", disc)
			Expect(err).NotTo(HaveOccurred())
			Expect(address).To(Equal("redfish-virtualmedia+https://10.141.0.1/redfish/v1/Systems/1"))
		})

		It("should resolve iDRAC address via discoverer", func() {
			info := &BMCInfo{IP: "10.141.0.5", Protocol: ProtocolDRAC}
			disc := &mockDiscoverer{systemPath: "/redfish/v1/Systems/System.Embedded.1"}

			address, err := Resolve(ctx, info, "aa:bb:cc:dd:ee:ff", "root", "pass", disc)
			Expect(err).NotTo(HaveOccurred())
			Expect(address).To(Equal("idrac-virtualmedia+https://10.141.0.5/redfish/v1/Systems/System.Embedded.1"))
		})

		It("should resolve iLO address via discoverer", func() {
			info := &BMCInfo{IP: "10.141.0.9", Protocol: ProtocolILO}
			disc := &mockDiscoverer{systemPath: "/redfish/v1/Systems/1"}

			address, err := Resolve(ctx, info, "aa:bb:cc:dd:ee:ff", "root", "pass", disc)
			Expect(err).NotTo(HaveOccurred())
			Expect(address).To(Equal("ilo5-virtualmedia+https://10.141.0.9/redfish/v1/Systems/1"))
		})

		It("should pass correct arguments to discoverer", func() {
			info := &BMCInfo{IP: "10.141.0.1", Protocol: ProtocolRedfish}
			disc := &mockDiscoverer{systemPath: "/redfish/v1/Systems/1"}

			_, err := Resolve(ctx, info, "AA:BB:CC:DD:EE:FF", "admin", "secret", disc)
			Expect(err).NotTo(HaveOccurred())
			Expect(disc.calledWith.bmcIP).To(Equal("10.141.0.1"))
			Expect(disc.calledWith.bootMAC).To(Equal("AA:BB:CC:DD:EE:FF"))
			Expect(disc.calledWith.username).To(Equal("admin"))
			Expect(disc.calledWith.password).To(Equal("secret"))
		})

		It("should return error when discoverer fails", func() {
			info := &BMCInfo{IP: "10.141.0.1", Protocol: ProtocolRedfish}
			disc := &mockDiscoverer{err: fmt.Errorf("%w: MAC not found", ErrNoMACMatch)}

			_, err := Resolve(ctx, info, "aa:bb:cc:dd:ee:ff", "root", "pass", disc)
			Expect(err).To(HaveOccurred())
			Expect(errors.Is(err, ErrNoMACMatch)).To(BeTrue())
			Expect(err.Error()).To(ContainSubstring("redfish discovery failed"))
		})

	})

	Context("error cases", func() {
		It("should return error for nil discoverer with Redfish protocol", func() {
			info := &BMCInfo{IP: "10.141.0.1", Protocol: ProtocolRedfish}

			_, err := Resolve(ctx, info, "aa:bb:cc:dd:ee:ff", "root", "pass", nil)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("discoverer is required"))
		})
	})

	Context("ExtractBMCInfo + Resolve integration", func() {
		It("should work end-to-end with ExtractBMCInfo", func() {
			interfaces := []DeviceInterface{
				{ChildType: "NetworkPhysicalInterface", Name: "eth0", IP: "10.0.0.10"},
				{ChildType: "NetworkBmcInterface", Name: "ipmi0", IP: "10.141.0.1"},
			}

			info, err := ExtractBMCInfo(interfaces, "NetworkBmcInterface")
			Expect(err).NotTo(HaveOccurred())

			address, err := Resolve(ctx, info, "aa:bb:cc:dd:ee:ff", "root", "pass", nil)
			Expect(err).NotTo(HaveOccurred())
			Expect(address).To(Equal("ipmi://10.141.0.1"))
		})
	})
})
