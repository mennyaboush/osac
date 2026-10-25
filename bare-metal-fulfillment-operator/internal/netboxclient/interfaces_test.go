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

package netboxclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("NetBox device interface listing", Label("OSAC-5953"), func() {
	It("HTTP-01 filters by saved device ID and projects the native primary MAC", func() {
		var calls atomic.Int32
		_, client := newTrustedClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			Expect(r.Method).To(Equal(http.MethodGet))
			Expect(r.URL.Path).To(Equal("/api/dcim/interfaces/"))
			Expect(r.URL.Query().Get("device_id")).To(Equal("42"))
			Expect(r.URL.Query().Get("limit")).To(Equal("100"))
			Expect(r.URL.Query().Get("offset")).To(Equal("0"))
			Expect(r.URL.Query()).NotTo(HaveKey("name"))
			Expect(r.Header.Get("Authorization")).To(Equal("Token " + testToken))

			record := nativeInterfaceResponse(501, 42, "eno1", "AA:BB:CC:DD:EE:01", map[string]any{"osac_logical_port": "data-0"})
			record["mac_address"] = "52:54:00:16:04:83"
			record["mac_addresses"] = []any{map[string]any{
				"id": 702, "url": "/api/dcim/mac-addresses/702/", "display": "52:54:00:16:04:83", "mac_address": "52:54:00:16:04:83",
			}}
			writeJSON(w, http.StatusOK, nativeInterfacePage(1, nil, record))
		}))

		var got []DeviceInterface
		err := client.ForEachDeviceInterface(context.Background(), "42", func(value DeviceInterface) (bool, error) {
			got = append(got, value)
			return true, nil
		})

		Expect(err).NotTo(HaveOccurred())
		Expect(calls.Load()).To(Equal(int32(1)))
		Expect(got).To(Equal([]DeviceInterface{{
			ID: "501", DeviceID: "42", Name: "eno1", PrimaryMAC: "AA:BB:CC:DD:EE:01",
			CustomFields: map[string]interface{}{"osac_logical_port": "data-0"},
		}}))
	})

	DescribeTable("HTTP-03 leaves absent primary relations empty",
		func(primaryPresent bool, primary any) {
			_, client := newTrustedClient(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				record := nativeInterfaceResponse(501, 42, "eno1", "", nil)
				if primaryPresent {
					record["primary_mac_address"] = primary
				} else {
					delete(record, "primary_mac_address")
				}
				record["mac_address"] = "52:54:00:16:04:83"
				record["mac_addresses"] = []any{map[string]any{
					"id": 702, "url": "/api/dcim/mac-addresses/702/", "display": "52:54:00:16:04:83", "mac_address": "52:54:00:16:04:83",
				}}
				writeJSON(w, http.StatusOK, nativeInterfacePage(1, nil, record))
			}))

			var got DeviceInterface
			err := client.ForEachDeviceInterface(context.Background(), "42", func(value DeviceInterface) (bool, error) {
				got = value
				return true, nil
			})

			Expect(err).NotTo(HaveOccurred())
			Expect(got.PrimaryMAC).To(BeEmpty())
		},
		Entry("omitted primary relation", false, nil),
		Entry("null primary relation", true, nil),
	)

	It("HTTP-04 preserves native name and alias fields without interpreting labels", func() {
		_, client := newTrustedClient(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			record := nativeInterfaceResponse(501, 42, "eno1", "AA:BB:CC:DD:EE:01", map[string]any{"osac_logical_port": "data-0"})
			record["label"] = "physical-label"
			record["tags"] = []any{map[string]any{
				"id": 8, "url": "/api/extras/tags/8/", "display": "ignored-tag",
				"name": "ignored-tag", "slug": "ignored-tag",
			}}
			writeJSON(w, http.StatusOK, nativeInterfacePage(1, nil, record))
		}))

		var got DeviceInterface
		err := client.ForEachDeviceInterface(context.Background(), "42", func(value DeviceInterface) (bool, error) {
			got = value
			return true, nil
		})

		Expect(err).NotTo(HaveOccurred())
		Expect(got.Name).To(Equal("eno1"))
		Expect(got.CustomFields).To(Equal(map[string]interface{}{"osac_logical_port": "data-0"}))
	})

	It("HTTP-05 accepts an empty interface list", func() {
		var calls atomic.Int32
		_, client := newTrustedClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			Expect(r.URL.Query().Get("device_id")).To(Equal("42"))
			writeJSON(w, http.StatusOK, nativeInterfacePage(0, nil))
		}))

		err := client.ForEachDeviceInterface(context.Background(), "42", func(DeviceInterface) (bool, error) {
			Fail("visitor called for empty result")
			return true, nil
		})

		Expect(err).NotTo(HaveOccurred())
		Expect(calls.Load()).To(Equal(int32(1)))
	})

	It("HTTP-06 follows pages at the configured origin using the next offset", func() {
		var calls atomic.Int32
		_, client := newTrustedClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			call := calls.Add(1)
			Expect(r.URL.Query().Get("device_id")).To(Equal("42"))
			Expect(r.URL.Query().Get("limit")).To(Equal("100"))
			if call == 1 {
				Expect(r.URL.Query().Get("offset")).To(Equal("0"))
				writeJSON(w, http.StatusOK, nativeInterfacePage(3,
					"https://foreign.example.test/api/dcim/interfaces/?device_id=99&offset=2",
					nativeInterfaceResponse(501, 42, "eno1", "", nil),
					nativeInterfaceResponse(502, 42, "eno2", "", nil)))
				return
			}
			Expect(r.URL.Query().Get("offset")).To(Equal("2"))
			writeJSON(w, http.StatusOK, nativeInterfacePage(3, nil,
				nativeInterfaceResponse(503, 42, "eno3", "", nil)))
		}))

		var ids []string
		err := client.ForEachDeviceInterface(context.Background(), "42", func(value DeviceInterface) (bool, error) {
			ids = append(ids, value.ID)
			return true, nil
		})

		Expect(err).NotTo(HaveOccurred())
		Expect(calls.Load()).To(Equal(int32(2)))
		Expect(ids).To(Equal([]string{"501", "502", "503"}))
	})

	It("HTTP-07 stops when the visitor returns false", func() {
		var calls atomic.Int32
		_, client := newTrustedClient(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls.Add(1)
			writeJSON(w, http.StatusOK, nativeInterfacePage(2, "https://foreign.example.test/next",
				nativeInterfaceResponse(501, 42, "eno1", "", nil)))
		}))

		var visits int
		err := client.ForEachDeviceInterface(context.Background(), "42", func(DeviceInterface) (bool, error) {
			visits++
			return false, nil
		})

		Expect(err).NotTo(HaveOccurred())
		Expect(visits).To(Equal(1))
		Expect(calls.Load()).To(Equal(int32(1)))
	})

	It("HTTP-08 propagates visitor errors and stops", func() {
		sentinel := errors.New("visitor rejected interface")
		var calls atomic.Int32
		_, client := newTrustedClient(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls.Add(1)
			writeJSON(w, http.StatusOK, nativeInterfacePage(2, nil,
				nativeInterfaceResponse(501, 42, "eno1", "", nil),
				nativeInterfaceResponse(502, 42, "eno2", "", nil)))
		}))

		var visits int
		err := client.ForEachDeviceInterface(context.Background(), "42", func(DeviceInterface) (bool, error) {
			visits++
			return true, sentinel
		})

		Expect(errors.Is(err, sentinel)).To(BeTrue())
		Expect(visits).To(Equal(1))
		Expect(calls.Load()).To(Equal(int32(1)))
	})

	It("HTTP-09 rejects invalid requests before I/O", func() {
		var calls atomic.Int32
		_, client := newTrustedClient(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			calls.Add(1)
		}))
		visit := func(DeviceInterface) (bool, error) { return true, nil }

		Expect(client.ForEachDeviceInterface(context.Background(), "42", nil)).To(MatchError(&APIError{Kind: ErrorKindInvalidRequest}))
		for _, id := range []string{"", "abc", "0", "-1", "2147483648"} {
			Expect(client.ForEachDeviceInterface(context.Background(), id, visit)).To(MatchError(&APIError{Kind: ErrorKindInvalidRequest}))
		}
		Expect(calls.Load()).To(BeZero())
	})

	DescribeTable("HTTP-10 rejects malformed pages before visiting",
		func(body string) {
			_, client := newTrustedClient(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, err := w.Write([]byte(body))
				Expect(err).NotTo(HaveOccurred())
			}))

			var visits int
			err := client.ForEachDeviceInterface(context.Background(), "42", func(DeviceInterface) (bool, error) {
				visits++
				return true, nil
			})

			Expect(err).To(HaveOccurred())
			var apiErr *APIError
			Expect(errors.As(err, &apiErr)).To(BeTrue())
			Expect(apiErr.Kind).To(Equal(ErrorKindInvalidResponse))
			Expect(visits).To(BeZero())
		},
		Entry("invalid JSON", "{"),
		Entry("wrong results shape", "{\"count\":1,\"next\":null,\"previous\":null,\"results\":{}}"),
		Entry("null page", "null"),
		Entry("missing interface fields", "{\"count\":1,\"next\":null,\"previous\":null,\"results\":[{\"id\":501}]}"),
		Entry("primary MAC is missing its required value", "{\"count\":1,\"next\":null,\"previous\":null,\"results\":[{\"id\":501,\"url\":\"/i/\",\"display\":\"eno1\",\"device\":{\"id\":42,\"url\":\"/d/\",\"display\":\"d\"},\"name\":\"eno1\",\"type\":{},\"link_peers\":[],\"connected_endpoints_reachable\":false,\"count_ipaddresses\":0,\"count_fhrp_groups\":0,\"_occupied\":false,\"primary_mac_address\":{\"id\":701,\"url\":\"/m/\",\"display\":\"x\",\"mac_address\":\"\"}}]}"),
		Entry("primary MAC null in a populated relation", "{\"count\":1,\"next\":null,\"previous\":null,\"results\":[{\"id\":501,\"url\":\"/i/\",\"display\":\"eno1\",\"device\":{\"id\":42,\"url\":\"/d/\",\"display\":\"d\"},\"name\":\"eno1\",\"type\":{},\"link_peers\":[],\"connected_endpoints_reachable\":false,\"count_ipaddresses\":0,\"count_fhrp_groups\":0,\"_occupied\":false,\"primary_mac_address\":{\"id\":701,\"url\":\"/m/\",\"display\":\"x\",\"mac_address\":null}}]}"),
	)

	DescribeTable("HTTP-11 rejects invalid pagination metadata",
		func(count int, next any, results []map[string]any) {
			_, client := newTrustedClient(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				writeJSON(w, http.StatusOK, nativeInterfacePage(count, next, results...))
			}))

			var visits int
			err := client.ForEachDeviceInterface(context.Background(), "42", func(DeviceInterface) (bool, error) {
				visits++
				return true, nil
			})

			Expect(err).To(HaveOccurred())
			var apiErr *APIError
			Expect(errors.As(err, &apiErr)).To(BeTrue())
			Expect(apiErr.Kind).To(Equal(ErrorKindInvalidResponse))
			Expect(visits).To(BeZero())
		},
		Entry("negative count", -1, nil, []map[string]any{}),
		Entry("page over limit", 101, nil, makeInterfaceResults(101)),
		Entry("empty page with next", 1, "https://foreign.example.test/next", []map[string]any{}),
		Entry("next at count boundary", 1, "https://foreign.example.test/next", []map[string]any{nativeInterfaceResponse(501, 42, "eno1", "", nil)}),
	)

	It("HTTP-12 never contacts a host returned in the next URL", func() {
		var foreignCalls atomic.Int32
		foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			foreignCalls.Add(1)
			w.WriteHeader(http.StatusOK)
		}))
		DeferCleanup(foreign.Close)

		var calls atomic.Int32
		_, client := newTrustedClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if calls.Add(1) == 1 {
				writeJSON(w, http.StatusOK, nativeInterfacePage(2, foreign.URL+"/api/dcim/interfaces/?device_id=999&token=fixture-attacker-token",
					nativeInterfaceResponse(501, 42, "eno1", "", nil)))
				return
			}
			Expect(r.URL.Query().Get("device_id")).To(Equal("42"))
			Expect(r.URL.Query().Get("offset")).To(Equal("1"))
			Expect(r.URL.Query()).NotTo(HaveKey("token"))
			writeJSON(w, http.StatusOK, nativeInterfacePage(2, nil,
				nativeInterfaceResponse(502, 42, "eno2", "", nil)))
		}))

		err := client.ForEachDeviceInterface(context.Background(), "42", func(DeviceInterface) (bool, error) {
			return true, nil
		})

		Expect(err).NotTo(HaveOccurred())
		Expect(calls.Load()).To(Equal(int32(2)))
		Expect(foreignCalls.Load()).To(BeZero())
	})

	DescribeTable("HTTP-13 rejects an invalid interface or parent identity",
		func(record map[string]any) {
			_, client := newTrustedClient(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				writeJSON(w, http.StatusOK, nativeInterfacePage(1, nil, record))
			}))

			var visits int
			err := client.ForEachDeviceInterface(context.Background(), "42", func(DeviceInterface) (bool, error) {
				visits++
				return true, nil
			})

			Expect(err).To(HaveOccurred())
			var apiErr *APIError
			Expect(errors.As(err, &apiErr)).To(BeTrue())
			Expect(apiErr.Kind).To(Equal(ErrorKindInvalidResponse))
			Expect(visits).To(BeZero())
		},
		Entry("zero interface ID", nativeInterfaceResponse(0, 42, "eno1", "", nil)),
		Entry("negative interface ID", nativeInterfaceResponse(-1, 42, "eno1", "", nil)),
		Entry("zero device ID", nativeInterfaceResponse(501, 0, "eno1", "", nil)),
		Entry("different device ID", nativeInterfaceResponse(501, 43, "eno1", "", nil)),
	)

	DescribeTable("HTTP-14 classifies permanent API failures",
		func(status int, kind ErrorKind) {
			_, client := newTrustedClient(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "sensitive-provider-body", status)
			}))

			err := client.ForEachDeviceInterface(context.Background(), "42", func(DeviceInterface) (bool, error) {
				Fail("visitor called after API failure")
				return true, nil
			})
			expectAPIError(err, kind, status)
			Expect(err.Error()).NotTo(ContainSubstring("sensitive-provider-body"))
		},
		Entry("bad request", http.StatusBadRequest, ErrorKindRequestRejected),
		Entry("unauthorized", http.StatusUnauthorized, ErrorKindUnauthorized),
		Entry("forbidden", http.StatusForbidden, ErrorKindForbidden),
		Entry("not found", http.StatusNotFound, ErrorKindNotFound),
	)

	DescribeTable("HTTP-15 retries temporary GET failures",
		func(status int) {
			var calls atomic.Int32
			_, client := newTrustedClient(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if calls.Add(1) == 1 {
					http.Error(w, "temporary", status)
					return
				}
				writeJSON(w, http.StatusOK, nativeInterfacePage(1, nil,
					nativeInterfaceResponse(501, 42, "eno1", "", nil)))
			}))

			var visits int
			err := client.ForEachDeviceInterface(context.Background(), "42", func(DeviceInterface) (bool, error) {
				visits++
				return true, nil
			})

			Expect(err).NotTo(HaveOccurred())
			Expect(calls.Load()).To(Equal(int32(2)))
			Expect(visits).To(Equal(1))
		},
		Entry("request timeout", http.StatusRequestTimeout),
		Entry("rate limited", http.StatusTooManyRequests),
		Entry("internal server error", http.StatusInternalServerError),
		Entry("service unavailable", http.StatusServiceUnavailable),
	)

	It("HTTP-16 stops after max GET attempts and keeps the error sanitized", func() {
		var calls atomic.Int32
		_, client := newTrustedClient(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls.Add(1)
			http.Error(w, "sensitive-provider-body", http.StatusServiceUnavailable)
		}))

		err := client.ForEachDeviceInterface(context.Background(), "42", func(DeviceInterface) (bool, error) {
			Fail("visitor called after API failure")
			return true, nil
		})

		expectAPIError(err, ErrorKindUnavailable, http.StatusServiceUnavailable)
		Expect(calls.Load()).To(Equal(int32(maxGETAttempts)))
		Expect(err.Error()).NotTo(ContainSubstring("sensitive-provider-body"))
	})

	It("HTTP-17 performs no request for a pre-cancelled context", func() {
		var calls atomic.Int32
		_, client := newTrustedClient(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		err := client.ForEachDeviceInterface(ctx, "42", func(DeviceInterface) (bool, error) { return true, nil })

		Expect(errors.Is(err, context.Canceled)).To(BeTrue())
		Expect(calls.Load()).To(BeZero())
	})

	It("HTTP-18 checks cancellation between pages", func() {
		var calls atomic.Int32
		_, client := newTrustedClient(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls.Add(1)
			writeJSON(w, http.StatusOK, nativeInterfacePage(2, "https://foreign.example.test/next",
				nativeInterfaceResponse(501, 42, "eno1", "", nil)))
		}))
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		err := client.ForEachDeviceInterface(ctx, "42", func(DeviceInterface) (bool, error) {
			cancel()
			return true, nil
		})

		Expect(errors.Is(err, context.Canceled)).To(BeTrue())
		Expect(calls.Load()).To(Equal(int32(1)))
	})

	It("HTTP-19 cancels an in-flight request promptly", func() {
		started := make(chan struct{}, 1)
		_, client := newTrustedClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			started <- struct{}{}
			<-r.Context().Done()
		}))
		ctx, cancel := context.WithCancel(context.Background())
		result := make(chan error, 1)
		go func() {
			result <- client.ForEachDeviceInterface(ctx, "42", func(DeviceInterface) (bool, error) { return true, nil })
		}()

		Eventually(started).WithTimeout(2 * time.Second).Should(Receive())
		cancel()
		Eventually(result).WithTimeout(2 * time.Second).Should(Receive(MatchError(context.Canceled)))
	})

	It("HTTP-20 cancels the GET retry wait without issuing another request", func() {
		unavailable := make(chan struct{}, 1)
		var calls atomic.Int32
		_, client := newTrustedClient(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls.Add(1)
			http.Error(w, "temporary", http.StatusServiceUnavailable)
			unavailable <- struct{}{}
		}))
		ctx, cancel := context.WithCancel(context.Background())
		result := make(chan error, 1)
		go func() {
			result <- client.ForEachDeviceInterface(ctx, "42", func(DeviceInterface) (bool, error) { return true, nil })
		}()

		Eventually(unavailable).WithTimeout(2 * time.Second).Should(Receive())
		cancel()
		Eventually(result).WithTimeout(2 * time.Second).Should(Receive(MatchError(context.Canceled)))
		Expect(calls.Load()).To(Equal(int32(1)))
	})

	It("HTTP-21 omits provider body and endpoint details from errors", func() {
		secret := "fixture-secret-that-must-not-escape"
		credentialURL := "https://netbox-user:fixture-password@netbox.example.test/api/"
		metadata := "raw-inventory-metadata host=fixture-baremetal-42"
		_, client := newTrustedClient(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, fmt.Sprintf("%s %s %s", secret, credentialURL, metadata), http.StatusForbidden)
		}))

		err := client.ForEachDeviceInterface(context.Background(), "42", func(DeviceInterface) (bool, error) { return true, nil })

		Expect(err).To(HaveOccurred())
		var apiErr *APIError
		Expect(errors.As(err, &apiErr)).To(BeTrue())
		Expect(apiErr.Kind).To(Equal(ErrorKindForbidden))
		expectDoesNotContain(err.Error(), secret, credentialURL, "fixture-password", metadata)
	})

	It("HTTP-22 retains TLS validation and rejects redirects", func() {
		var foreignCalls atomic.Int32
		foreign := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			foreignCalls.Add(1)
			writeJSON(w, http.StatusOK, nativeInterfacePage(0, nil))
		}))
		DeferCleanup(foreign.Close)

		_, client := newTrustedClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, foreign.URL+"/api/dcim/interfaces/", http.StatusFound)
		}))

		err := client.ForEachDeviceInterface(context.Background(), "42", func(DeviceInterface) (bool, error) { return true, nil })

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("redirect"))
		Expect(foreignCalls.Load()).To(BeZero())
	})

	It("HTTP-22 rejects TLS certificates outside configured roots", func() {
		var calls atomic.Int32
		server := httptest.NewUnstartedServer(ginkgoRequestHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls.Add(1)
			writeJSON(w, http.StatusOK, nativeInterfacePage(0, nil))
		})))
		server.Config.ErrorLog = log.New(io.Discard, "", 0)
		server.StartTLS()
		DeferCleanup(server.Close)

		client, err := New(Config{Endpoint: server.URL, TokenFile: writeTestToken()})
		Expect(err).NotTo(HaveOccurred())

		err = client.ForEachDeviceInterface(context.Background(), "42", func(DeviceInterface) (bool, error) { return true, nil })

		expectAPIError(err, ErrorKindTransport, 0)
		Expect(calls.Load()).To(BeZero())
		expectDoesNotContain(err.Error(), server.URL, testToken)
	})

	It("HTTP-23 accepts a nil context", func() {
		var ctx context.Context
		_, client := newTrustedClient(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, nativeInterfacePage(0, nil))
		}))

		Expect(client.ForEachDeviceInterface(ctx, "42", func(DeviceInterface) (bool, error) { return true, nil })).To(Succeed())
	})

	It("HTTP-24 reports a later-page failure after the first visitor call", func() {
		var calls atomic.Int32
		_, client := newTrustedClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if calls.Add(1) == 1 {
				writeJSON(w, http.StatusOK, nativeInterfacePage(2, "https://foreign.example.test/next",
					nativeInterfaceResponse(501, 42, "eno1", "", nil)))
				return
			}
			http.Error(w, "forbidden", http.StatusForbidden)
		}))

		var ids []string
		err := client.ForEachDeviceInterface(context.Background(), "42", func(value DeviceInterface) (bool, error) {
			ids = append(ids, value.ID)
			return true, nil
		})

		expectAPIError(err, ErrorKindForbidden, http.StatusForbidden)
		Expect(ids).To(Equal([]string{"501"}))
		Expect(calls.Load()).To(Equal(int32(2)))
	})

	It("HTTP-25 includes all native interface categories without extra filters", func() {
		var calls atomic.Int32
		_, client := newTrustedClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			Expect(r.URL.Query()).To(HaveKey("device_id"))
			Expect(r.URL.Query()).NotTo(HaveKey("enabled"))
			Expect(r.URL.Query()).NotTo(HaveKey("mgmt_only"))
			Expect(r.URL.Query()).NotTo(HaveKey("type"))
			disabled := nativeInterfaceResponse(501, 42, "eno1", "", nil)
			disabled["enabled"] = false
			disabled["mgmt_only"] = true
			virtual := nativeInterfaceResponse(502, 42, "veth0", "", nil)
			ordinary := nativeInterfaceResponse(503, 42, "ens3", "", nil)
			ordinary["enabled"] = true
			ordinary["mgmt_only"] = false
			writeJSON(w, http.StatusOK, nativeInterfacePage(3, nil, disabled, virtual, ordinary))
		}))

		var names []string
		err := client.ForEachDeviceInterface(context.Background(), "42", func(value DeviceInterface) (bool, error) {
			names = append(names, value.Name)
			return true, nil
		})

		Expect(err).NotTo(HaveOccurred())
		Expect(calls.Load()).To(Equal(int32(1)))
		Expect(names).To(Equal([]string{"eno1", "veth0", "ens3"}))
	})

	It("HTTP-26 checks cancellation after a successful page response", func() {
		_, client := newTrustedClient(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			Fail("request should use the controlled test transport")
		}))
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		body, err := json.Marshal(nativeInterfacePage(1, nil,
			nativeInterfaceResponse(501, 42, "eno1", "AA:BB:CC:DD:EE:01", nil)))
		Expect(err).NotTo(HaveOccurred())
		var calls atomic.Int32
		client.api.GetConfig().HTTPClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			calls.Add(1)
			header := make(http.Header)
			header.Set("Content-Type", "application/json")
			return &http.Response{
				StatusCode: http.StatusOK,
				Status:     "200 OK",
				Header:     header,
				Body:       &cancelContextOnCloseBody{Reader: strings.NewReader(string(body)), cancel: cancel},
				Request:    request,
			}, nil
		})}

		var visited []string
		err = client.ForEachDeviceInterface(ctx, "42", func(value DeviceInterface) (bool, error) {
			visited = append(visited, value.ID)
			return true, nil
		})

		Expect(errors.Is(err, context.Canceled)).To(BeTrue())
		Expect(visited).To(BeEmpty())
		Expect(calls.Load()).To(Equal(int32(1)))
	})

	It("HTTP-27 checks cancellation between records on one page", func() {
		var calls atomic.Int32
		_, client := newTrustedClient(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls.Add(1)
			writeJSON(w, http.StatusOK, nativeInterfacePage(2, nil,
				nativeInterfaceResponse(501, 42, "eno1", "AA:BB:CC:DD:EE:01", nil),
				nativeInterfaceResponse(502, 42, "eno2", "AA:BB:CC:DD:EE:02", nil)))
		}))
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		var visited []string
		err := client.ForEachDeviceInterface(ctx, "42", func(value DeviceInterface) (bool, error) {
			visited = append(visited, value.ID)
			cancel()
			return true, nil
		})

		Expect(errors.Is(err, context.Canceled)).To(BeTrue())
		Expect(visited).To(Equal([]string{"501"}))
		Expect(calls.Load()).To(Equal(int32(1)))
	})
})

type cancelContextOnCloseBody struct {
	io.Reader
	cancel context.CancelFunc
}

func (body *cancelContextOnCloseBody) Close() error {
	body.cancel()
	return nil
}

func nativeInterfaceResponse(id, deviceID int, name, primaryMAC string, customFields map[string]any) map[string]any {
	var primary any
	if primaryMAC != "" {
		primaryID := id + 200
		primary = map[string]any{
			"id": primaryID, "url": fmt.Sprintf("/api/dcim/mac-addresses/%d/", primaryID),
			"display": primaryMAC, "mac_address": primaryMAC,
		}
	}
	record := map[string]any{
		"id": id, "url": fmt.Sprintf("/api/dcim/interfaces/%d/", id), "display": name,
		"device": map[string]any{"id": deviceID, "url": fmt.Sprintf("/api/dcim/devices/%d/", deviceID), "display": "fixture-server"},
		"name":   name, "type": map[string]any{"value": "1000base-t", "label": "1000BASE-T (1GE)"},
		"link_peers": []any{}, "connected_endpoints_reachable": false,
		"count_ipaddresses": 0, "count_fhrp_groups": 0, "_occupied": false,
		"primary_mac_address": primary,
	}
	if customFields != nil {
		record["custom_fields"] = customFields
	}
	return record
}

func nativeInterfacePage(count int, next any, results ...map[string]any) map[string]any {
	if results == nil {
		results = []map[string]any{}
	}
	return map[string]any{"count": count, "next": next, "previous": nil, "results": results}
}

func makeInterfaceResults(count int) []map[string]any {
	results := make([]map[string]any, count)
	for i := range results {
		id := 1000 + i
		results[i] = nativeInterfaceResponse(id, 42, "eno"+strconv.Itoa(i), "", nil)
	}
	return results
}
