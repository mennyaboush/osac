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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/osac-project/osac/bare-metal-fulfillment-operator/internal/baremetalhost"
)

func TestNetBoxClientGetHostLogicalPortMACsNotImplemented(t *testing.T) {
	macs, err := (&NetBoxClient{}).GetHostLogicalPortMACs(context.Background(), "baremetal/netbox-42")
	if !errors.Is(err, errNetBoxClientNotImplemented) {
		t.Fatalf("GetHostLogicalPortMACs error = %v, want %v", err, errNetBoxClientNotImplemented)
	}
	if macs != nil {
		t.Fatalf("GetHostLogicalPortMACs returned %v, want nil", macs)
	}
}

func TestParseNetBoxOptions(t *testing.T) {
	tests := []struct {
		name    string
		options map[string]any
		want    *NetBoxClientConfig
		wantErr string
	}{
		{name: "missing options", options: map[string]any{}, wantErr: "netbox options not found in config"},
		{name: "wrong value type", options: map[string]any{"netbox": "not-a-map"}, wantErr: "failed to parse netbox options"},
		{name: "missing URL", options: map[string]any{"netbox": map[string]any{"tokenFile": "/var/run/secrets/netbox/token"}}, wantErr: "netbox url is required in config"},
		{name: "missing token file", options: map[string]any{"netbox": map[string]any{"url": "https://netbox.example.test"}}, wantErr: "netbox tokenFile is required in config"},
		{
			name: "valid options",
			options: map[string]any{"netbox": map[string]any{
				"url":               "https://netbox.example.test/",
				"tokenFile":         "/var/run/secrets/netbox/token",
				"caFile":            "/var/run/secrets/netbox/ca.crt",
				"allowInsecureHTTP": true,
			}},
			want: &NetBoxClientConfig{
				URL:               "https://netbox.example.test/",
				TokenFile:         "/var/run/secrets/netbox/token",
				CAFile:            "/var/run/secrets/netbox/ca.crt",
				AllowInsecureHTTP: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseNetBoxOptions(tt.options)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("ParseNetBoxOptions() error = %v, want substring %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseNetBoxOptions() error = %v", err)
			}
			if *got != *tt.want {
				t.Fatalf("ParseNetBoxOptions() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestNewClientSelectsRegisteredNetBoxBackend(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("test-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	client, err := NewClient(context.Background(), &Config{
		Type:      "netbox",
		HostClass: netBoxHostClass,
		Options: map[string]any{
			"netbox": map[string]any{
				"url":       "https://netbox.example.test/",
				"tokenFile": tokenFile,
			},
		},
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	adapter, ok := client.(*NetBoxClient)
	if !ok {
		t.Fatalf("NewClient() type = %T, want *NetBoxClient", client)
	}
	if adapter.api == nil {
		t.Fatal("NewClient() left the NetBox API client nil")
	}
	if adapter.hostClass != netBoxHostClass {
		t.Fatalf("NetBox hostClass = %q, want %s", adapter.hostClass, netBoxHostClass)
	}
}

func TestNetBoxClientSetBMHLifecycleManager(t *testing.T) {
	adapter := &NetBoxClient{}
	manager := baremetalhost.NewManager(nil, nil, "metal3-system")
	if err := adapter.SetBMHLifecycleManager(manager); err != nil {
		t.Fatalf("SetBMHLifecycleManager() error = %v", err)
	}
	if adapter.bmhManager != manager {
		t.Fatal("SetBMHLifecycleManager() did not retain the supplied manager")
	}
	if adapter.bmhManager.Namespace() != "metal3-system" {
		t.Fatalf("injected manager namespace = %q, want metal3-system", adapter.bmhManager.Namespace())
	}
	if err := adapter.SetBMHLifecycleManager(nil); err == nil {
		t.Fatal("SetBMHLifecycleManager(nil) succeeded, want an error")
	}
}

func TestNewNetBoxClientRejectsInvalidConfiguration(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr string
	}{
		{name: "nil config", wantErr: "netbox inventory config is required"},
		{name: "missing host class", config: &Config{}, wantErr: "NetBox backend requires inventory.hostClass=metal3"},
		{name: "wrong host class", config: &Config{HostClass: "netbox"}, wantErr: "NetBox backend requires inventory.hostClass=metal3"},
		{name: "missing netbox options", config: &Config{HostClass: netBoxHostClass}, wantErr: "netbox options not found in config"},
		{
			name: "HTTP URL",
			config: &Config{HostClass: netBoxHostClass, Options: map[string]any{"netbox": map[string]any{
				"url":       "http://netbox.example.test",
				"tokenFile": "/unused/token",
			}}},
			wantErr: "NetBox HTTP endpoints require AllowInsecureHTTP",
		},
		{
			name: "unreadable token file",
			config: &Config{HostClass: netBoxHostClass, Options: map[string]any{"netbox": map[string]any{
				"url":       "https://netbox.example.test",
				"tokenFile": filepath.Join(t.TempDir(), "missing-token"),
			}}},
			wantErr: "token file is missing or invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewNetBoxClient(context.Background(), tt.config)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("NewNetBoxClient() error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestParseNetBoxOptionsRejectsUnmarshalableValue(t *testing.T) {
	_, err := ParseNetBoxOptions(map[string]any{"netbox": make(chan int)})
	if err == nil || !strings.Contains(err.Error(), "failed to parse netbox options") {
		t.Fatalf("ParseNetBoxOptions() error = %v, want JSON marshal failure", err)
	}
}

func TestNetBoxStubMethodsReturnNotImplemented(t *testing.T) {
	client := &NetBoxClient{}
	ctx := context.Background()

	host, err := client.FindFreeHost(ctx, map[string]string{"region": "lab"})
	if !errors.Is(err, errNetBoxClientNotImplemented) || host != nil {
		t.Fatalf("FindFreeHost() = (%#v, %v), want (nil, %v)", host, err, errNetBoxClientNotImplemented)
	}

	host, err = client.AssignHost(ctx, "baremetal/netbox-42", "provider-42", map[string]string{"region": "lab"})
	if !errors.Is(err, errNetBoxClientNotImplemented) || host != nil {
		t.Fatalf("AssignHost() = (%#v, %v), want (nil, %v)", host, err, errNetBoxClientNotImplemented)
	}

	err = client.UnassignHost(ctx, "baremetal/netbox-42", []string{"192.0.2.42"})
	if !errors.Is(err, errNetBoxClientNotImplemented) {
		t.Fatalf("UnassignHost() error = %v, want %v", err, errNetBoxClientNotImplemented)
	}

	nics, err := client.GetHostNICs(ctx, "baremetal/netbox-42")
	if !errors.Is(err, errNetBoxClientNotImplemented) || nics != nil {
		t.Fatalf("GetHostNICs() = (%#v, %v), want (nil, %v)", nics, err, errNetBoxClientNotImplemented)
	}
}
