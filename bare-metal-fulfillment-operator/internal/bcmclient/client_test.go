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

package bcmclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"

	. "github.com/onsi/ginkgo/v2" //nolint:revive,staticcheck
	. "github.com/onsi/gomega"    //nolint:revive,staticcheck
)

func mustWrite(w http.ResponseWriter, body string) {
	_, err := fmt.Fprint(w, body)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
}

func newTestServer(handler http.Handler) (*httptest.Server, *http.Client) {
	server := httptest.NewTLSServer(handler)
	DeferCleanup(server.Close)
	return server, server.Client()
}

func expectJSONCall(r *http.Request, expectedService, expectedCall string) json.RawMessage {
	ExpectWithOffset(1, r.Method).To(Equal(http.MethodPost))
	ExpectWithOffset(1, r.URL.Path).To(Equal(jsonPath))

	var req struct {
		Service string          `json:"service"`
		Call    string          `json:"call"`
		Args    json.RawMessage `json:"args"`
	}
	ExpectWithOffset(1, json.NewDecoder(r.Body).Decode(&req)).To(Succeed())
	ExpectWithOffset(1, req.Service).To(Equal(expectedService))
	ExpectWithOffset(1, req.Call).To(Equal(expectedCall))
	return req.Args
}

var _ = Describe("BCM Client", func() {
	var ctx context.Context

	BeforeEach(func() {
		ctx = context.Background()
	})

	Describe("Config validation", func() {
		It("should accept a valid config", func() {
			cfg := &Config{
				URL:      "https://bcm-head:8081",
				CertFile: "/certs/tls.crt",
				KeyFile:  "/certs/tls.key",
			}
			Expect(cfg.Validate()).To(Succeed())
		})

		It("should return error when url is missing", func() {
			cfg := &Config{CertFile: "/certs/tls.crt", KeyFile: "/certs/tls.key"}
			Expect(cfg.Validate()).To(MatchError(ContainSubstring("bcm url is required")))
		})

		It("should return error when certFile is missing", func() {
			cfg := &Config{URL: "https://bcm-head:8081", KeyFile: "/certs/tls.key"}
			Expect(cfg.Validate()).To(MatchError(ContainSubstring("bcm certFile is required")))
		})

		It("should return error when keyFile is missing", func() {
			cfg := &Config{URL: "https://bcm-head:8081", CertFile: "/certs/tls.crt"}
			Expect(cfg.Validate()).To(MatchError(ContainSubstring("bcm keyFile is required")))
		})
	})

	Describe("checkVersion", func() {
		It("should succeed with a valid version", func() {
			server, client := newTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				Expect(r.URL.Path).To(Equal(versionPath))
				w.Header().Set("Content-Type", "application/json")
				mustWrite(w, `{"cm_version":"11.0","cmd_version":"3.1","build_hash":"abc","build_index":1,"database_version":1}`)
			}))

			c := NewClientForTest(client, server.URL)
			Expect(c.checkVersion(ctx)).To(Succeed())
		})

		It("should return ErrVersionTooOld for an old version", func() {
			server, client := newTestServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				mustWrite(w, `{"cm_version":"9.2","cmd_version":"2.0","build_hash":"old","build_index":1,"database_version":1}`)
			}))

			c := NewClientForTest(client, server.URL)
			Expect(c.checkVersion(ctx)).To(MatchError(ContainSubstring(ErrVersionTooOld.Error())))
		})

		It("should succeed with the exact minimum version", func() {
			server, client := newTestServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				mustWrite(w, `{"cm_version":"10.25.03","cmd_version":"3.0","build_hash":"min","build_index":1,"database_version":1}`)
			}))

			c := NewClientForTest(client, server.URL)
			Expect(c.checkVersion(ctx)).To(Succeed())
		})

		It("should reject version with old patch", func() {
			server, client := newTestServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				mustWrite(w, `{"cm_version":"10.25.02","cmd_version":"3.0","build_hash":"old-patch","build_index":1,"database_version":1}`)
			}))

			c := NewClientForTest(client, server.URL)
			Expect(c.checkVersion(ctx)).To(MatchError(ContainSubstring(ErrVersionTooOld.Error())))
		})

		It("should reject version without patch component", func() {
			server, client := newTestServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				mustWrite(w, `{"cm_version":"10.25","cmd_version":"3.0","build_hash":"no-patch","build_index":1,"database_version":1}`)
			}))

			c := NewClientForTest(client, server.URL)
			Expect(c.checkVersion(ctx)).To(MatchError(ContainSubstring(ErrVersionTooOld.Error())))
		})

		It("should accept higher minor version without patch", func() {
			server, client := newTestServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				mustWrite(w, `{"cm_version":"10.26","cmd_version":"3.0","build_hash":"newer","build_index":1,"database_version":1}`)
			}))

			c := NewClientForTest(client, server.URL)
			Expect(c.checkVersion(ctx)).To(Succeed())
		})

		It("should return ErrServerError on HTTP 500", func() {
			server, client := newTestServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			}))

			c := NewClientForTest(client, server.URL)
			Expect(c.checkVersion(ctx)).To(MatchError(ContainSubstring(ErrServerError.Error())))
		})
	})

	Describe("GetDevices", func() {
		It("should return a list of devices", func() {
			server, client := newTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				expectJSONCall(r, "cmdevice", "getDevices")
				w.Header().Set("Content-Type", "application/json")
				mustWrite(w, `[
					{"baseType":"Device","childType":"LiteNode","uuid":"uuid1","hostname":"node001","mac":"aa:bb:cc:dd:ee:01","extra_values":{"resource_class":"h100"}},
					{"baseType":"Device","childType":"PhysicalNode","uuid":"uuid2","hostname":"head01","mac":"aa:bb:cc:dd:ee:02","extra_values":null}
				]`)
			}))

			c := NewClientForTest(client, server.URL)
			devices, err := c.GetDevices(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(devices).To(HaveLen(2))
			Expect(devices[0].Hostname).To(Equal("node001"))
			Expect(devices[0].ChildType).To(Equal("LiteNode"))
			Expect(devices[0].Raw).NotTo(BeNil())
		})

		It("should return an empty list", func() {
			server, client := newTestServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				mustWrite(w, `[]`)
			}))

			c := NewClientForTest(client, server.URL)
			devices, err := c.GetDevices(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(devices).To(BeEmpty())
		})
	})

	Describe("GetDevice", func() {
		It("should return a device when found", func() {
			server, client := newTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				args := expectJSONCall(r, "cmdevice", "getDevice")
				var positionalArgs []string
				Expect(json.Unmarshal(args, &positionalArgs)).To(Succeed())
				Expect(positionalArgs).To(Equal([]string{"node001"}))
				w.Header().Set("Content-Type", "application/json")
				mustWrite(w, `{"baseType":"Device","childType":"LiteNode","uuid":"uuid1","hostname":"node001","mac":"aa:bb:cc:dd:ee:01","extra_values":{"resource_class":"h100"}}`)
			}))

			c := NewClientForTest(client, server.URL)
			device, err := c.GetDevice(ctx, "node001")
			Expect(err).NotTo(HaveOccurred())
			Expect(device).NotTo(BeNil())
			Expect(device.Hostname).To(Equal("node001"))
			Expect(device.ExtraValues["resource_class"]).To(Equal("h100"))
		})

		It("should return nil when device is not found", func() {
			server, client := newTestServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				mustWrite(w, `null`)
			}))

			c := NewClientForTest(client, server.URL)
			device, err := c.GetDevice(ctx, "nonexistent")
			Expect(err).NotTo(HaveOccurred())
			Expect(device).To(BeNil())
		})
	})

	Describe("UpdateDevice", func() {
		It("should succeed on a successful update", func() {
			server, client := newTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				expectJSONCall(r, "cmdevice", "updateDevice")
				w.Header().Set("Content-Type", "application/json")
				mustWrite(w, `{"success":true,"task_uuid":"00000000-0000-0000-0000-000000000000","updated_entity":null,"validation":[]}`)
			}))

			c := NewClientForTest(client, server.URL)
			resp, err := c.UpdateDevice(ctx, json.RawMessage(`{"baseType":"Device","childType":"LiteNode","hostname":"node001"}`))
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.Success).To(BeTrue())
		})

		It("should return ValidationError on validation failure", func() {
			server, client := newTestServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				mustWrite(w, `{"success":false,"task_uuid":"00000000-0000-0000-0000-000000000000","updated_entity":null,"validation":[{"baseType":"Validation","error_code":"NOT_NULL","field":"partition","message":"partition is required","severity":"ERROR"}]}`)
			}))

			c := NewClientForTest(client, server.URL)
			resp, err := c.UpdateDevice(ctx, json.RawMessage(`{"baseType":"Device","hostname":"node001"}`))
			Expect(err).To(HaveOccurred())
			Expect(resp).NotTo(BeNil())

			var valErr *ValidationError
			Expect(errors.As(err, &valErr)).To(BeTrue())
			Expect(valErr.Validations).To(HaveLen(1))
			Expect(valErr.Validations[0].ErrorCode).To(Equal("NOT_NULL"))
		})

		It("should return error on success:false with no validations", func() {
			server, client := newTestServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				mustWrite(w, `{"success":false,"task_uuid":"00000000-0000-0000-0000-000000000000","updated_entity":null,"validation":[]}`)
			}))

			c := NewClientForTest(client, server.URL)
			_, err := c.UpdateDevice(ctx, json.RawMessage(`{"baseType":"Device","hostname":"node001"}`))
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("bcm reported failure"))
		})
	})

	Describe("doJSONCall", func() {
		It("should return ErrAuthFailed on certificate error message", func() {
			server, client := newTestServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				mustWrite(w, `{"errormessage":"Your certificate (profile:) does not allow access to CMDevice::getDevices\n"}`)
			}))

			c := NewClientForTest(client, server.URL)
			_, err := c.doJSONCall(ctx, "cmdevice", "getDevices", []any{})
			Expect(err).To(HaveOccurred())
			Expect(err).To(MatchError(ContainSubstring(ErrAuthFailed.Error())))
		})

		It("should return a generic error on unknown service", func() {
			server, client := newTestServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				mustWrite(w, `{"errormessage":"No such service: '(cm)fake'\n"}`)
			}))

			c := NewClientForTest(client, server.URL)
			_, err := c.doJSONCall(ctx, "cmfake", "getDevices", []any{})
			Expect(err).To(HaveOccurred())
			Expect(errors.Is(err, ErrAuthFailed)).To(BeFalse())
		})

		It("should return ErrServerError on HTTP 500", func() {
			server, client := newTestServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
				mustWrite(w, "internal error")
			}))

			c := NewClientForTest(client, server.URL)
			_, err := c.doJSONCall(ctx, "cmdevice", "getDevices", []any{})
			Expect(err).To(HaveOccurred())
			Expect(err).To(MatchError(ContainSubstring(ErrServerError.Error())))
		})

		It("should return ErrAuthFailed on HTTP 401", func() {
			server, client := newTestServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusUnauthorized)
			}))

			c := NewClientForTest(client, server.URL)
			_, err := c.doJSONCall(ctx, "cmdevice", "getDevices", []any{})
			Expect(err).To(HaveOccurred())
			Expect(err).To(MatchError(ContainSubstring(ErrAuthFailed.Error())))
		})

		It("should return a generic error on HTTP 404", func() {
			server, client := newTestServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNotFound)
			}))

			c := NewClientForTest(client, server.URL)
			_, err := c.doJSONCall(ctx, "cmdevice", "getDevices", []any{})
			Expect(err).To(HaveOccurred())
			Expect(errors.Is(err, ErrAuthFailed)).To(BeFalse())
			Expect(errors.Is(err, ErrServerError)).To(BeFalse())
		})

		It("should return ErrConnectionFailed on connection error", func() {
			c := NewClientForTest(&http.Client{}, "https://localhost:1")
			_, err := c.doJSONCall(ctx, "cmdevice", "getDevices", []any{})
			Expect(err).To(HaveOccurred())
			Expect(err).To(MatchError(ContainSubstring(ErrConnectionFailed.Error())))
		})

		It("should default nil args to empty array", func() {
			server, client := newTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				args := expectJSONCall(r, "cmdevice", "getDevices")
				Expect(string(args)).To(Equal("[]"))
				w.Header().Set("Content-Type", "application/json")
				mustWrite(w, `[]`)
			}))

			c := NewClientForTest(client, server.URL)
			_, err := c.doJSONCall(ctx, "cmdevice", "getDevices", nil)
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Describe("SetExtraValue", func() {
		It("should add a key to existing extra_values", func() {
			raw := json.RawMessage(`{"hostname":"node001","extra_values":{"resource_class":"h100"}}`)
			updated, err := SetExtraValue(raw, "osac_instance_id", "test-uid-123")
			Expect(err).NotTo(HaveOccurred())

			var obj map[string]any
			Expect(json.Unmarshal(updated, &obj)).To(Succeed())
			ev := obj["extra_values"].(map[string]any)
			Expect(ev["osac_instance_id"]).To(Equal("test-uid-123"))
			Expect(ev["resource_class"]).To(Equal("h100"))
		})

		It("should create extra_values when null", func() {
			raw := json.RawMessage(`{"hostname":"node001","extra_values":null}`)
			updated, err := SetExtraValue(raw, "osac_instance_id", "test-uid-123")
			Expect(err).NotTo(HaveOccurred())

			var obj map[string]any
			Expect(json.Unmarshal(updated, &obj)).To(Succeed())
			ev := obj["extra_values"].(map[string]any)
			Expect(ev["osac_instance_id"]).To(Equal("test-uid-123"))
		})
	})

	Describe("RemoveExtraValue", func() {
		It("should remove a key and preserve others", func() {
			raw := json.RawMessage(`{"hostname":"node001","extra_values":{"resource_class":"h100","osac_instance_id":"uid-123"}}`)
			updated, err := RemoveExtraValue(raw, "osac_instance_id")
			Expect(err).NotTo(HaveOccurred())

			var obj map[string]any
			Expect(json.Unmarshal(updated, &obj)).To(Succeed())
			ev := obj["extra_values"].(map[string]any)
			Expect(ev).NotTo(HaveKey("osac_instance_id"))
			Expect(ev["resource_class"]).To(Equal("h100"))
		})
	})

	Describe("classifyHTTPError", func() {
		DescribeTable("should classify transport errors",
			func(err error, expected error) {
				result := classifyHTTPError(err)
				if expected == nil {
					Expect(result).ToNot(HaveOccurred())
				} else {
					Expect(result).To(MatchError(ContainSubstring(expected.Error())))
				}
			},
			Entry("nil error", nil, nil),
			Entry("tls keyword", fmt.Errorf("tls: handshake failure"), ErrTLSFailed),
			Entry("x509 keyword", fmt.Errorf("x509: certificate signed by unknown authority"), ErrTLSFailed),
			Entry("certificate keyword", fmt.Errorf("remote error: certificate required"), ErrTLSFailed),
			Entry("generic connection error", fmt.Errorf("dial tcp 10.0.0.1:8081: connect: connection refused"), ErrConnectionFailed),
		)
	})

	Describe("ValidationError", func() {
		It("should format validation details in the error message", func() {
			err := &ValidationError{
				Validations: []Validation{
					{ErrorCode: "NOT_NULL", Field: "partition", Message: "partition is required"},
					{ErrorCode: "BAD_VALUE", Field: "uuid", Message: "invalid UUID"},
				},
			}
			Expect(err.Error()).To(ContainSubstring("partition"))
			Expect(err.Error()).To(ContainSubstring("NOT_NULL"))
			Expect(err.Error()).To(ContainSubstring("BAD_VALUE"))
		})
	})
})
