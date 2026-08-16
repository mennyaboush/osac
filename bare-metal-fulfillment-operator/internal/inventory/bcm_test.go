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
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	. "github.com/onsi/ginkgo/v2" //nolint:revive,staticcheck
	. "github.com/onsi/gomega"    //nolint:revive,staticcheck

	"github.com/osac-project/osac/bare-metal-fulfillment-operator/internal/bcmclient"
)

func TestBCMInventoryAdapter(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "BCM Inventory Adapter Suite")
}

var _ = Describe("BCM Inventory Adapter", func() {
	Describe("NewBCMClient", func() {
		It("should return error when bcm key is missing from options", func() {
			cfg := &Config{
				Type:      "bcm",
				HostClass: "bcm",
				Options:   map[string]any{},
			}
			_, err := NewBCMClient(context.Background(), cfg)
			Expect(err).To(MatchError(ContainSubstring("bcm options not found in config")))
		})

		It("should return error when url is missing", func() {
			cfg := &Config{
				Type:      "bcm",
				HostClass: "bcm",
				Options: map[string]any{
					"bcm": map[string]any{
						"credentialsSecret": "osac-bcm-certs",
					},
				},
			}
			_, err := NewBCMClient(context.Background(), cfg)
			Expect(err).To(MatchError(ContainSubstring("bcm url is required in config")))
		})

		It("should return error when credentialsSecret is missing", func() {
			cfg := &Config{
				Type:      "bcm",
				HostClass: "bcm",
				Options: map[string]any{
					"bcm": map[string]any{
						"url": "https://bcm-head:8081",
					},
				},
			}
			_, err := NewBCMClient(context.Background(), cfg)
			Expect(err).To(MatchError(ContainSubstring("bcm credentialsSecret is required in config")))
		})

		It("should return error when bcm options are invalid", func() {
			cfg := &Config{
				Type:      "bcm",
				HostClass: "bcm",
				Options: map[string]any{
					"bcm": "not-a-map",
				},
			}
			_, err := NewBCMClient(context.Background(), cfg)
			Expect(err).To(MatchError(ContainSubstring("failed to unmarshal bcm options")))
		})
	})

	Describe("Registration", func() {
		It("should register the bcm type in the client factory", func() {
			_, ok := newClientFuncs["bcm"]
			Expect(ok).To(BeTrue())
		})
	})

	Describe("NewBCMClientForTest", func() {
		var (
			server *httptest.Server
			client *BCMClient
		)

		BeforeEach(func() {
			server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, err := fmt.Fprint(w, `{"cm_version":"11.0"}`)
				Expect(err).NotTo(HaveOccurred())
			}))
			DeferCleanup(server.Close)

			bcm := bcmclient.NewClientForTest(server.Client(), server.URL)
			client = NewBCMClientForTest(bcm, nil, "bcm")
		})

		It("should create a BCMClient with the provided dependencies", func() {
			Expect(client).NotTo(BeNil())
			Expect(client.hostClass).To(Equal("bcm"))
			Expect(client.bmhManager).To(BeNil())
		})
	})

	Describe("Stub methods", func() {
		var client *BCMClient

		BeforeEach(func() {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, err := fmt.Fprint(w, `{}`)
				Expect(err).NotTo(HaveOccurred())
			}))
			DeferCleanup(server.Close)

			bcm := bcmclient.NewClientForTest(server.Client(), server.URL)
			client = NewBCMClientForTest(bcm, nil, "bcm")
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
