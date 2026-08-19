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
	"testing"

	. "github.com/onsi/ginkgo/v2" //nolint:revive,staticcheck
	. "github.com/onsi/gomega"    //nolint:revive,staticcheck

	"sigs.k8s.io/controller-runtime/pkg/certwatcher"
)

type mockBCMAPI struct{}

func (m *mockBCMAPI) CertWatcher() *certwatcher.CertWatcher { return nil }

func TestBCMInventoryAdapter(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "BCM Inventory Adapter Suite")
}

var _ = Describe("BCM Inventory Adapter", func() {
	Describe("ParseBCMOptions", func() {
		It("should return error when bcm key is missing from options", func() {
			_, err := ParseBCMOptions(map[string]any{})
			Expect(err).To(MatchError(ContainSubstring("bcm options not found in config")))
		})

		It("should return error when url is missing", func() {
			_, err := ParseBCMOptions(map[string]any{
				"bcm": map[string]any{
					"credentialsSecret": "osac-bcm-certs",
				},
			})
			Expect(err).To(MatchError(ContainSubstring("bcm url is required in config")))
		})

		It("should return error when credentialsSecret is missing", func() {
			_, err := ParseBCMOptions(map[string]any{
				"bcm": map[string]any{
					"url": "https://bcm-head:8081",
				},
			})
			Expect(err).To(MatchError(ContainSubstring("bcm credentialsSecret is required in config")))
		})

		It("should return error when bcm options are invalid", func() {
			_, err := ParseBCMOptions(map[string]any{
				"bcm": "not-a-map",
			})
			Expect(err).To(MatchError(ContainSubstring("failed to unmarshal bcm options")))
		})

		It("should parse valid options", func() {
			cfg, err := ParseBCMOptions(map[string]any{
				"bcm": map[string]any{
					"url":                "https://bcm-head:8081",
					"credentialsSecret":  "osac-bcm-certs",
					"insecureSkipVerify": true,
				},
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(cfg.URL).To(Equal("https://bcm-head:8081"))
			Expect(cfg.CredentialsSecret).To(Equal("osac-bcm-certs"))
			Expect(cfg.InsecureSkipVerify).To(BeTrue())
		})

		It("should reject credentialsSecret that escapes cert directory", func() {
			_, err := ParseBCMOptions(map[string]any{
				"bcm": map[string]any{
					"url":               "https://bcm-head:8081",
					"credentialsSecret": "../../etc/shadow",
				},
			})
			Expect(err).To(MatchError(ContainSubstring("resolves outside cert directory")))
		})
	})

	Describe("NewBCMClient", func() {
		It("should create a BCMClient with the provided dependencies", func() {
			client := NewBCMClient(&mockBCMAPI{}, nil, "bcm")
			Expect(client).NotTo(BeNil())
			Expect(client.hostClass).To(Equal("bcm"))
			Expect(client.bmhManager).To(BeNil())
		})
	})

	Describe("Stub methods", func() {
		var client *BCMClient

		BeforeEach(func() {
			client = NewBCMClient(&mockBCMAPI{}, nil, "bcm")
		})

		It("should return not-implemented error from FindFreeHost", func() {
			host, err := client.FindFreeHost(context.Background(), nil)
			Expect(err).To(MatchError(ContainSubstring("not implemented")))
			Expect(host).To(BeNil())
		})

		It("should return not-implemented error from AssignHost", func() {
			host, err := client.AssignHost(context.Background(), "ns/host1", "bmi-123", nil)
			Expect(err).To(MatchError(ContainSubstring("not implemented")))
			Expect(host).To(BeNil())
		})

		It("should return not-implemented error from UnassignHost", func() {
			err := client.UnassignHost(context.Background(), "ns/host1", nil)
			Expect(err).To(MatchError(ContainSubstring("not implemented")))
		})
	})
})
