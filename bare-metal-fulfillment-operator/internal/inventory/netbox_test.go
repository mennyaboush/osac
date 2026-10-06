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
	"testing"

	"k8s.io/apimachinery/pkg/util/validation"
)

func TestNewNetBoxHostIdentity(t *testing.T) {
	tests := []struct {
		name       string
		namespace  string
		deviceID   int64
		wantName   string
		wantHostID string
		wantErr    bool
	}{
		{name: "canonical identity", namespace: "baremetal", deviceID: 42, wantName: "netbox-42", wantHostID: "baremetal/netbox-42"},
		{name: "zero ID", namespace: "baremetal", deviceID: 0, wantName: "netbox-0", wantHostID: "baremetal/netbox-0"},
		{name: "negative ID", namespace: "baremetal", deviceID: -42, wantName: "netbox--42", wantHostID: "baremetal/netbox--42"},
		{name: "maximum int64 produces a Kubernetes-safe name", namespace: "baremetal", deviceID: 9223372036854775807, wantName: "netbox-9223372036854775807", wantHostID: "baremetal/netbox-9223372036854775807"},
		{name: "namespace containing a path separator", namespace: "bare/metal", deviceID: 42, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := newNetBoxHostIdentity(tt.namespace, tt.deviceID)
			if (err != nil) != tt.wantErr {
				t.Fatalf("newNetBoxHostIdentity(%q, %d) error = %v, wantErr %t", tt.namespace, tt.deviceID, err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if got.deviceID != tt.deviceID || got.name != tt.wantName || got.inventoryHostID != tt.wantHostID {
				t.Fatalf("newNetBoxHostIdentity(%q, %d) = %#v", tt.namespace, tt.deviceID, got)
			}
			if problems := validation.IsDNS1035Label(got.name); len(problems) != 0 {
				t.Fatalf("generated name %q is not a DNS-1035 label: %v", got.name, problems)
			}

			namespace, name, err := ParseHostID(got.inventoryHostID)
			if err != nil || namespace != got.namespace || name != got.name {
				t.Fatalf("generated inventory host ID %q is incompatible with namespace/name parsing: (%q, %q, %v)", got.inventoryHostID, namespace, name, err)
			}
		})
	}
}

func TestParseNetBoxHostIdentity(t *testing.T) {
	tests := []struct {
		name            string
		inventoryHostID string
		configuredNS    string
		wantDeviceID    int64
		wantName        string
		wantErr         bool
	}{
		{name: "persisted identity", inventoryHostID: "baremetal/netbox-42", configuredNS: "baremetal", wantDeviceID: 42, wantName: "netbox-42"},
		{name: "zero ID", inventoryHostID: "baremetal/netbox-0", configuredNS: "baremetal", wantDeviceID: 0, wantName: "netbox-0"},
		{name: "negative ID", inventoryHostID: "baremetal/netbox--42", configuredNS: "baremetal", wantDeviceID: -42, wantName: "netbox--42"},
		{name: "wrong namespace", inventoryHostID: "other/netbox-42", configuredNS: "baremetal", wantErr: true},
		{name: "missing namespace", inventoryHostID: "netbox-42", configuredNS: "baremetal", wantErr: true},
		{name: "empty namespace", inventoryHostID: "/netbox-42", configuredNS: "", wantErr: true},
		{name: "extra path component", inventoryHostID: "baremetal/netbox-42/other", configuredNS: "baremetal", wantErr: true},
		{name: "wrong name prefix", inventoryHostID: "baremetal/worker-42", configuredNS: "baremetal", wantErr: true},
		{name: "non-canonical ID", inventoryHostID: "baremetal/netbox-042", configuredNS: "baremetal", wantErr: true},
		{name: "non-canonical signed ID", inventoryHostID: "baremetal/netbox-+42", configuredNS: "baremetal", wantErr: true},
		{name: "overflow ID", inventoryHostID: "baremetal/netbox-9223372036854775808", configuredNS: "baremetal", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseNetBoxHostIdentity(tt.inventoryHostID, tt.configuredNS)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseNetBoxHostIdentity(%q, %q) error = %v, wantErr %t", tt.inventoryHostID, tt.configuredNS, err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if got.namespace != tt.configuredNS || got.deviceID != tt.wantDeviceID || got.name != tt.wantName || got.inventoryHostID != tt.inventoryHostID {
				t.Fatalf("parseNetBoxHostIdentity(%q, %q) = %#v", tt.inventoryHostID, tt.configuredNS, got)
			}
		})
	}
}
