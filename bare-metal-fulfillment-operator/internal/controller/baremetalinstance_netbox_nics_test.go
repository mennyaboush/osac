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

package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/osac-project/osac/bare-metal-fulfillment-operator/api/v1alpha1"
	"github.com/osac-project/osac/bare-metal-fulfillment-operator/internal/baremetalhost"
	"github.com/osac-project/osac/bare-metal-fulfillment-operator/internal/inventory"
	"github.com/osac-project/osac/bare-metal-fulfillment-operator/internal/netboxclient"
	opv1alpha1 "github.com/osac-project/osac/osac-operator/api/v1alpha1"
	"github.com/osac-project/osac/osac-operator/pkg/provisioning"
)

type osac5953NetBoxPage struct {
	offset     int
	count      int
	next       bool
	results    []map[string]any
	statusCode int
	rawBody    string
}

type osac5953HandoffCase struct {
	attachmentInterface string
	pages               []osac5953NetBoxPage
	requestCount        int32
	wantMACs            map[string]string
	handoffComplete     bool
	hardwareMAC         string
}

var _ = Describe("OSAC-5953 native NetBox NIC handoff", Label("OSAC-5953"), func() {
	DescribeTable("resolves logical MACs through the real NetBox and inventory clients",
		func(testCase osac5953HandoffCase) {
			server, requests := newOSAC5953NetBoxServer(testCase.pages...)
			DeferCleanup(server.Close)

			manager := baremetalhost.NewMockBMHLifecycleManager(gomock.NewController(GinkgoT()))
			manager.EXPECT().Namespace().Return("baremetal").AnyTimes()
			manager.EXPECT().GetHardwareNICs(gomock.Any(), gomock.Any()).Times(0)
			inventoryClient := newOSAC5953InventoryClient(server, manager)

			bmi := newOSAC5953BareMetalInstance(testCase.attachmentInterface)
			if testCase.handoffComplete {
				bmi.SetStatusCondition(v1alpha1.HostConditionNetworkHandoffComplete,
					metav1.ConditionTrue, "Succeeded", "Handoff complete")
			}
			if testCase.hardwareMAC != "" {
				bmi.Status.Hardware = &v1alpha1.BareMetalHardware{
					NICs: []v1alpha1.BareMetalNICStatus{{MAC: testCase.hardwareMAC}},
				}
			}

			var triggerCount int
			var jobMACs map[string]string
			provider := &mockProvisioningProvider{
				triggerProvisionFunc: func(jobCtx context.Context, resource client.Object) (*provisioning.ProvisionResult, error) {
					triggerCount++
					jobMACs = provisioning.NetworkAttachmentMACsFromContext(jobCtx)
					jobBMI := resource.(*v1alpha1.BareMetalInstance)
					Expect(jobBMI.Spec.NetworkAttachments[0].Interface).To(Equal(testCase.attachmentInterface))
					return &provisioning.ProvisionResult{
						JobID:        "osac-5953-netbox-job",
						InitialState: opv1alpha1.JobStatePending,
					}, nil
				},
			}
			reconciler := &BareMetalInstanceReconciler{
				Client:                        k8sClient,
				Scheme:                        k8sClient.Scheme(),
				InventoryClient:               inventoryClient,
				IPDiscoveryProvider:           provider,
				ProvisionPollIntervalDuration: time.Second,
			}

			result, err := reconciler.reconcileIPDiscovery(context.Background(), bmi)

			Expect(err).NotTo(HaveOccurred())
			if testCase.handoffComplete {
				Expect(triggerCount).To(Equal(1))
				Expect(jobMACs).To(Equal(testCase.wantMACs))
			} else {
				Expect(triggerCount).To(BeZero())
				Expect(result.RequeueAfter).To(BeNumerically(">", 0))
			}
			Expect(requests.Load()).To(Equal(testCase.requestCount))
			Expect(bmi.Spec.NetworkAttachments[0].Interface).To(Equal(testCase.attachmentInterface))
			if testCase.hardwareMAC != "" {
				Expect(bmi.Status.Hardware.NICs).To(Equal([]v1alpha1.BareMetalNICStatus{{MAC: testCase.hardwareMAC}}))
			}
		},
		Entry("CTRL-01 sends an explicit interface alias to the DHCP job", osac5953HandoffCase{
			attachmentInterface: "data-0",
			handoffComplete:     true,
			requestCount:        1,
			pages: []osac5953NetBoxPage{{
				offset: 0, count: 1,
				results: []map[string]any{
					newOSAC5953NetBoxInterface(501, "eno1", "AA:BB:CC:DD:EE:01", map[string]any{"osac_logical_port": "data-0"}),
				},
			}},
			wantMACs: map[string]string{"subnet-1": "aa:bb:cc:dd:ee:01"},
		}),
		Entry("CTRL-02 uses an exact native interface name without an alias", osac5953HandoffCase{
			attachmentInterface: "data-0",
			handoffComplete:     true,
			requestCount:        1,
			pages: []osac5953NetBoxPage{{
				offset: 0, count: 1,
				results: []map[string]any{newOSAC5953NetBoxInterface(501, "data-0", "AA:BB:CC:DD:EE:01", nil)},
			}},
			wantMACs: map[string]string{"subnet-1": "aa:bb:cc:dd:ee:01"},
		}),
		Entry("CTRL-03 selects data-0 when it appears before data-1", osac5953HandoffCase{
			attachmentInterface: "data-0",
			handoffComplete:     true,
			requestCount:        1,
			pages: []osac5953NetBoxPage{{
				offset: 0, count: 2,
				results: []map[string]any{
					newOSAC5953NetBoxInterface(501, "data-0", "AA:BB:CC:DD:EE:01", nil),
					newOSAC5953NetBoxInterface(502, "data-1", "AA:BB:CC:DD:EE:02", nil),
				},
			}},
			wantMACs: map[string]string{"subnet-1": "aa:bb:cc:dd:ee:01"},
		}),
		Entry("CTRL-03 selects data-0 when it appears after data-1", osac5953HandoffCase{
			attachmentInterface: "data-0",
			handoffComplete:     true,
			requestCount:        1,
			pages: []osac5953NetBoxPage{{
				offset: 0, count: 2,
				results: []map[string]any{
					newOSAC5953NetBoxInterface(502, "data-1", "AA:BB:CC:DD:EE:02", nil),
					newOSAC5953NetBoxInterface(501, "data-0", "AA:BB:CC:DD:EE:01", nil),
				},
			}},
			wantMACs: map[string]string{"subnet-1": "aa:bb:cc:dd:ee:01"},
		}),
		Entry("CTRL-04 keeps name matching when NetBox has no interfaces", osac5953HandoffCase{
			attachmentInterface: "data-0",
			handoffComplete:     true,
			requestCount:        1,
			pages:               []osac5953NetBoxPage{{offset: 0, count: 0, results: []map[string]any{}}},
		}),
		Entry("CTRL-05 keeps name matching when the selected interface is absent", osac5953HandoffCase{
			attachmentInterface: "data-0",
			handoffComplete:     true,
			requestCount:        1,
			pages: []osac5953NetBoxPage{{
				offset: 0, count: 1,
				results: []map[string]any{newOSAC5953NetBoxInterface(501, "eno1", "AA:BB:CC:DD:EE:01", nil)},
			}},
		}),
		Entry("CTRL-06 keeps name matching when the selected interface has no primary MAC", osac5953HandoffCase{
			attachmentInterface: "data-0",
			handoffComplete:     true,
			requestCount:        1,
			pages: []osac5953NetBoxPage{{
				offset: 0, count: 1,
				results: []map[string]any{
					newOSAC5953NetBoxInterface(501, "eno1", "", map[string]any{"osac_logical_port": "data-0"}),
				},
			}},
		}),
		Entry("CTRL-07 falls back when an alias has the wrong type", osac5953HandoffCase{
			attachmentInterface: "data-0",
			handoffComplete:     true,
			requestCount:        1,
			pages: []osac5953NetBoxPage{{
				offset: 0, count: 1,
				results: []map[string]any{
					newOSAC5953NetBoxInterface(501, "eno1", "AA:BB:CC:DD:EE:01", map[string]any{"osac_logical_port": true}),
				},
			}},
		}),
		Entry("CTRL-07 falls back when a primary MAC is malformed", osac5953HandoffCase{
			attachmentInterface: "data-0",
			handoffComplete:     true,
			requestCount:        1,
			pages: []osac5953NetBoxPage{{
				offset: 0, count: 1,
				results: []map[string]any{newOSAC5953NetBoxInterface(501, "data-0", "not-a-mac", nil)},
			}},
		}),
		Entry("CTRL-07 falls back on duplicate aliases", osac5953HandoffCase{
			attachmentInterface: "data-0",
			handoffComplete:     true,
			requestCount:        1,
			pages: []osac5953NetBoxPage{{
				offset: 0, count: 2,
				results: []map[string]any{
					newOSAC5953NetBoxInterface(501, "eno1", "AA:BB:CC:DD:EE:01", map[string]any{"osac_logical_port": "data-0"}),
					newOSAC5953NetBoxInterface(502, "eno2", "AA:BB:CC:DD:EE:02", map[string]any{"osac_logical_port": "data-0"}),
				},
			}},
		}),
		Entry("CTRL-07 falls back on alias and native-name conflicts", osac5953HandoffCase{
			attachmentInterface: "data-0",
			handoffComplete:     true,
			requestCount:        1,
			pages: []osac5953NetBoxPage{{
				offset: 0, count: 2,
				results: []map[string]any{
					newOSAC5953NetBoxInterface(501, "eno1", "AA:BB:CC:DD:EE:01", map[string]any{"osac_logical_port": "data-0"}),
					newOSAC5953NetBoxInterface(502, "data-0", "AA:BB:CC:DD:EE:02", nil),
				},
			}},
		}),
		Entry("CTRL-08 keeps name matching after a forbidden response", osac5953HandoffCase{
			attachmentInterface: "data-0",
			handoffComplete:     true,
			requestCount:        1,
			pages:               []osac5953NetBoxPage{{offset: 0, statusCode: http.StatusForbidden, rawBody: "forbidden"}},
		}),
		Entry("CTRL-08 keeps name matching after malformed JSON", osac5953HandoffCase{
			attachmentInterface: "data-0",
			handoffComplete:     true,
			requestCount:        1,
			pages:               []osac5953NetBoxPage{{offset: 0, rawBody: "{malformed"}},
		}),
		Entry("CTRL-08 discards page-one mappings when page two fails", osac5953HandoffCase{
			attachmentInterface: "data-0",
			handoffComplete:     true,
			requestCount:        2,
			pages: []osac5953NetBoxPage{
				{
					offset: 0, count: 2, next: true,
					results: []map[string]any{newOSAC5953NetBoxInterface(501, "data-0", "AA:BB:CC:DD:EE:01", nil)},
				},
				{offset: 1, count: 2, statusCode: http.StatusForbidden, rawBody: "forbidden"},
			},
		}),
		Entry("CTRL-09 binds requests to the persisted NetBox device ID", osac5953HandoffCase{
			attachmentInterface: "data-0",
			handoffComplete:     true,
			requestCount:        1,
			pages: []osac5953NetBoxPage{{
				offset: 0, count: 1,
				results: []map[string]any{newOSAC5953NetBoxInterface(501, "data-0", "AA:BB:CC:DD:EE:01", nil)},
			}},
			wantMACs: map[string]string{"subnet-1": "aa:bb:cc:dd:ee:01"},
		}),
		Entry("CTRL-10 uses the sole resolved interface for an unnamed attachment", osac5953HandoffCase{
			attachmentInterface: "",
			handoffComplete:     true,
			requestCount:        1,
			pages: []osac5953NetBoxPage{{
				offset: 0, count: 1,
				results: []map[string]any{newOSAC5953NetBoxInterface(501, "mgmt0", "AA:BB:CC:DD:EE:01", nil)},
			}},
			wantMACs: map[string]string{"subnet-1": "aa:bb:cc:dd:ee:01"},
		}),
		Entry("CTRL-11 does not guess for an unnamed attachment with multiple interfaces", osac5953HandoffCase{
			attachmentInterface: "",
			handoffComplete:     true,
			requestCount:        1,
			pages: []osac5953NetBoxPage{{
				offset: 0, count: 2,
				results: []map[string]any{
					newOSAC5953NetBoxInterface(501, "data-0", "AA:BB:CC:DD:EE:01", nil),
					newOSAC5953NetBoxInterface(502, "data-1", "AA:BB:CC:DD:EE:02", nil),
				},
			}},
		}),
		Entry("CTRL-15 waits for network handoff before requesting NetBox or dispatching DHCP", osac5953HandoffCase{
			attachmentInterface: "data-0",
			requestCount:        0,
			pages: []osac5953NetBoxPage{{
				offset: 0, count: 1,
				results: []map[string]any{newOSAC5953NetBoxInterface(501, "data-0", "AA:BB:CC:DD:EE:01", nil)},
			}},
		}),
		Entry("CTRL-17 keeps physical status MACs independent from logical DHCP MACs", osac5953HandoffCase{
			attachmentInterface: "data-0",
			handoffComplete:     true,
			hardwareMAC:         "aa:bb:cc:dd:ee:01",
			requestCount:        1,
			pages: []osac5953NetBoxPage{{
				offset: 0, count: 1,
				results: []map[string]any{newOSAC5953NetBoxInterface(501, "data-0", "AA:BB:CC:DD:EE:02", nil)},
			}},
			wantMACs: map[string]string{"subnet-1": "aa:bb:cc:dd:ee:02"},
		}),
	)

	It("CTRL-12 projects inspected NICs into hardware status without calling NetBox", func() {
		server, requests := newOSAC5953FailingNetBoxServer()
		DeferCleanup(server.Close)
		manager := baremetalhost.NewMockBMHLifecycleManager(gomock.NewController(GinkgoT()))
		manager.EXPECT().Namespace().Return("baremetal")
		manager.EXPECT().GetHardwareNICs(gomock.Any(), "netbox-42").Return([]string{
			"AA:BB:CC:DD:EE:01", "FF:00:11:22:33:44",
		}, nil)
		inventoryClient := newOSAC5953InventoryClient(server, manager)
		bmi := newOSAC5953BareMetalInstance("data-0")
		reconciler := &BareMetalInstanceReconciler{InventoryClient: inventoryClient}

		err := reconciler.reconcileNICMetadata(context.Background(), bmi)

		Expect(err).NotTo(HaveOccurred())
		Expect(bmi.Status.Hardware).NotTo(BeNil())
		Expect(bmi.Status.Hardware.NICs).To(Equal([]v1alpha1.BareMetalNICStatus{
			{MAC: "aa:bb:cc:dd:ee:01"}, {MAC: "ff:00:11:22:33:44"},
		}))
		Expect(requests.Load()).To(BeZero())
	})

	It("CTRL-13 stores empty inspection data and does not read it again", func() {
		server, requests := newOSAC5953FailingNetBoxServer()
		DeferCleanup(server.Close)
		manager := baremetalhost.NewMockBMHLifecycleManager(gomock.NewController(GinkgoT()))
		manager.EXPECT().Namespace().Return("baremetal")
		manager.EXPECT().GetHardwareNICs(gomock.Any(), "netbox-42").Return(nil, nil).Times(1)
		inventoryClient := newOSAC5953InventoryClient(server, manager)
		bmi := newOSAC5953BareMetalInstance("data-0")
		reconciler := &BareMetalInstanceReconciler{InventoryClient: inventoryClient}

		Expect(reconciler.reconcileNICMetadata(context.Background(), bmi)).To(Succeed())
		Expect(bmi.Status.Hardware).NotTo(BeNil())
		Expect(bmi.Status.Hardware.NICs).To(BeEmpty())
		Expect(reconciler.reconcileNICMetadata(context.Background(), bmi)).To(Succeed())
		Expect(requests.Load()).To(BeZero())
	})

	It("CTRL-14 propagates BMH inspection failures without populating hardware status", func() {
		server, requests := newOSAC5953FailingNetBoxServer()
		DeferCleanup(server.Close)
		backendErr := errors.New("BMH inspection unavailable")
		manager := baremetalhost.NewMockBMHLifecycleManager(gomock.NewController(GinkgoT()))
		manager.EXPECT().Namespace().Return("baremetal")
		manager.EXPECT().GetHardwareNICs(gomock.Any(), "netbox-42").Return(nil, backendErr)
		inventoryClient := newOSAC5953InventoryClient(server, manager)
		bmi := newOSAC5953BareMetalInstance("data-0")
		reconciler := &BareMetalInstanceReconciler{InventoryClient: inventoryClient}

		err := reconciler.reconcileNICMetadata(context.Background(), bmi)

		Expect(errors.Is(err, backendErr)).To(BeTrue())
		Expect(bmi.Status.Hardware).To(BeNil())
		Expect(requests.Load()).To(BeZero())
	})

	It("CTRL-18 does not query NetBox while polling an existing DHCP job", func() {
		server, requests := newOSAC5953FailingNetBoxServer()
		DeferCleanup(server.Close)
		manager := baremetalhost.NewMockBMHLifecycleManager(gomock.NewController(GinkgoT()))
		manager.EXPECT().Namespace().AnyTimes().Return("baremetal")
		inventoryClient := newOSAC5953InventoryClient(server, manager)
		bmi := newOSAC5953BareMetalInstance("data-0")
		bmi.SetStatusCondition(v1alpha1.HostConditionNetworkHandoffComplete,
			metav1.ConditionTrue, "Succeeded", "Handoff complete")
		bmi.Status.IPDiscoveryJobs = []opv1alpha1.JobStatus{{
			JobID: "existing-ip-discovery-job",
			Type:  opv1alpha1.JobTypeProvision,
			State: opv1alpha1.JobStatePending,
		}}

		var triggerCount, statusCount int
		provider := &mockProvisioningProvider{
			triggerProvisionFunc: func(context.Context, client.Object) (*provisioning.ProvisionResult, error) {
				triggerCount++
				return &provisioning.ProvisionResult{JobID: "unexpected-job", InitialState: opv1alpha1.JobStatePending}, nil
			},
			getProvisionStatusFunc: func(_ context.Context, _ client.Object, jobID string) (provisioning.ProvisionStatus, error) {
				statusCount++
				return provisioning.ProvisionStatus{JobID: jobID, State: opv1alpha1.JobStatePending}, nil
			},
		}
		reconciler := &BareMetalInstanceReconciler{
			Client:                        k8sClient,
			Scheme:                        k8sClient.Scheme(),
			InventoryClient:               inventoryClient,
			IPDiscoveryProvider:           provider,
			ProvisionPollIntervalDuration: time.Second,
		}

		result, err := reconciler.reconcileIPDiscovery(context.Background(), bmi)

		Expect(err).NotTo(HaveOccurred())
		Expect(result.RequeueAfter).To(BeNumerically(">", 0))
		Expect(triggerCount).To(BeZero())
		Expect(statusCount).To(Equal(1))
		Expect(requests.Load()).To(BeZero())
	})
})

func newOSAC5953BareMetalInstance(interfaceName string) *v1alpha1.BareMetalInstance {
	bmi := &v1alpha1.BareMetalInstance{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "osac-5953-netbox-",
			Namespace:    "default",
			Annotations: map[string]string{
				"osac.openshift.io/tenant":          "test-tenant",
				"osac.openshift.io/owner-reference": "ClusterOrder/test-order",
			},
		},
		Spec: v1alpha1.BareMetalInstanceSpec{
			ExternalHostID: "baremetal/netbox-42",
			HostClass:      "metal3",
			TemplateID:     "noop",
			Selector: v1alpha1.HostSelectorSpec{
				HostSelector: map[string]string{"osac.openshift.io/host-type": "test"},
			},
			NetworkAttachments: []v1alpha1.BareMetalNetworkAttachment{{
				SubnetRef: "subnet-1", Interface: interfaceName, Primary: true,
			}},
		},
	}
	Expect(k8sClient.Create(context.Background(), bmi)).To(Succeed())
	DeferCleanup(func() {
		Expect(k8sClient.Delete(context.Background(), bmi)).To(Succeed())
	})
	return bmi
}

func newOSAC5953InventoryClient(server *httptest.Server, manager *baremetalhost.MockBMHLifecycleManager) *inventory.NetBoxClient {
	tokenPath := filepath.Join(GinkgoT().TempDir(), "netbox-token")
	Expect(os.WriteFile(tokenPath, []byte("controller-fixture-token\n"), 0o600)).To(Succeed())
	info, err := os.Stat(tokenPath)
	Expect(err).NotTo(HaveOccurred())
	Expect(info.Mode().Perm()).To(Equal(os.FileMode(0o600)))

	api, err := netboxclient.New(netboxclient.Config{
		Endpoint:          server.URL,
		TokenFile:         tokenPath,
		AllowInsecureHTTP: true,
	})
	Expect(err).NotTo(HaveOccurred())
	return inventory.NewNetBoxClient(api, manager, "metal3")
}

func newOSAC5953NetBoxServer(pages ...osac5953NetBoxPage) (*httptest.Server, *atomic.Int32) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer GinkgoRecover()
		requests.Add(1)
		Expect(r.Method).To(Equal(http.MethodGet))
		Expect(r.URL.Path).To(Equal("/api/dcim/interfaces/"))
		Expect(r.URL.Query()).To(HaveLen(3))
		Expect(r.URL.Query().Get("device_id")).To(Equal("42"))
		Expect(r.URL.Query().Get("limit")).To(Equal("100"))
		Expect(r.URL.Query()).NotTo(HaveKey("name"))
		Expect(r.URL.Query()).NotTo(HaveKey("cf_osac_logical_port"))
		Expect(r.Header.Get("Authorization")).To(Equal("Token controller-fixture-token"))

		offset, err := strconv.Atoi(r.URL.Query().Get("offset"))
		Expect(err).NotTo(HaveOccurred())
		for _, page := range pages {
			if page.offset != offset {
				continue
			}
			status := page.statusCode
			if status == 0 {
				status = http.StatusOK
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			if page.rawBody != "" {
				_, _ = io.WriteString(w, page.rawBody)
				return
			}
			var next any
			if page.next {
				next = "https://other.example.test/api/dcim/interfaces/?offset=999"
			}
			if err := json.NewEncoder(w).Encode(map[string]any{
				"count": page.count, "next": next, "previous": nil, "results": page.results,
			}); err != nil {
				Fail(fmt.Sprintf("failed to encode NetBox test page: %v", err))
			}
			return
		}
		http.Error(w, "unexpected NetBox page offset", http.StatusNotFound)
	}))
	return server, &requests
}

func newOSAC5953FailingNetBoxServer() (*httptest.Server, *atomic.Int32) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		http.Error(w, "unexpected NetBox request", http.StatusInternalServerError)
	}))
	return server, &requests
}

func newOSAC5953NetBoxInterface(id int, name, primaryMAC string, customFields map[string]any) map[string]any {
	var primaryMACAddress any
	if primaryMAC != "" {
		primaryMACAddress = map[string]any{
			"id": id + 200, "url": fmt.Sprintf("/api/dcim/mac-addresses/%d/", id+200),
			"display": primaryMAC, "mac_address": primaryMAC,
		}
	}
	iface := map[string]any{
		"id": id, "url": fmt.Sprintf("/api/dcim/interfaces/%d/", id), "display": name,
		"device": map[string]any{"id": 42, "url": "/api/dcim/devices/42/", "display": "netbox-test-host"},
		"name":   name, "type": map[string]any{"value": "1000base-t", "label": "1000BASE-T (1GE)"},
		"link_peers": []any{}, "connected_endpoints_reachable": false,
		"count_ipaddresses": 0, "count_fhrp_groups": 0, "_occupied": false,
		"primary_mac_address": primaryMACAddress,
	}
	if customFields != nil {
		iface["custom_fields"] = customFields
	}
	return iface
}
