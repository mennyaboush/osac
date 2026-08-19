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
	. "github.com/onsi/ginkgo/v2" //nolint:revive,staticcheck
	. "github.com/onsi/gomega"    //nolint:revive,staticcheck
)

var _ = Describe("Discoverer interface", func() {
	It("should be implemented by GofishDiscoverer", func() {
		var d Discoverer = &GofishDiscoverer{}
		Expect(d).NotTo(BeNil())
	})

	It("should be implementable by mock", func() {
		var d Discoverer = &mockDiscoverer{systemPath: "/redfish/v1/Systems/1"}
		Expect(d).NotTo(BeNil())
	})
})

var _ = Describe("GofishDiscoverer", func() {
	It("should default InsecureSkipVerify to false", func() {
		d := &GofishDiscoverer{}
		Expect(d.InsecureSkipVerify).To(BeFalse())
	})

	It("should allow setting InsecureSkipVerify", func() {
		d := &GofishDiscoverer{InsecureSkipVerify: true}
		Expect(d.InsecureSkipVerify).To(BeTrue())
	})
})
