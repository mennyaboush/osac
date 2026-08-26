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

import "encoding/json"

// jsonRequest is the envelope for all BCM JSON API calls.
type jsonRequest struct {
	Service string `json:"service"`
	Call    string `json:"call"`
	Args    any    `json:"args"`
}

// DeviceInterface represents a network interface entry from a BCM
// device's interfaces array. Only fields needed for BMC discovery
// are included.
type DeviceInterface struct {
	ChildType string `json:"childType"`
	Name      string `json:"name"`
	IP        string `json:"ip"`
}

// BMCSettings holds the BMC login credentials stored natively in a BCM
// device/category/partition object. It is optional on any object and, when
// unset, comes back as an empty object (userName/password == "").
type BMCSettings struct {
	UserName string `json:"userName"`
	Password string `json:"password"`
	UserID   int    `json:"userID"`
}

// Credentials returns the username and password and whether both are present.
// An empty-but-present bmcSettings object (BCM's representation of "unset")
// returns ok == false so callers never build a Secret from blank creds.
func (b *BMCSettings) Credentials() (username, password string, ok bool) {
	if b == nil || b.UserName == "" || b.Password == "" {
		return "", "", false
	}
	return b.UserName, b.Password, true
}

// Device represents a BCM device with typed access to OSAC-relevant
// fields plus the raw JSON needed for full-object update round-trips.
//
// Category and Partition are the UUIDs of the objects the device belongs to;
// BMC credentials may be inherited from them (resolution order:
// device → category → partition). BMCSettings holds only the device's own
// (non-inherited) BMC credentials — the BCM JSON API never returns the
// resolved/inherited value on the device object.
type Device struct {
	BaseType    string            `json:"baseType"`
	ChildType   string            `json:"childType"`
	UUID        string            `json:"uuid"`
	Hostname    string            `json:"hostname"`
	MAC         string            `json:"mac"`
	ExtraValues map[string]any    `json:"extra_values"`
	Interfaces  []DeviceInterface `json:"interfaces"`
	BMCSettings *BMCSettings      `json:"bmcSettings"`
	Category    string            `json:"category"`
	Partition   string            `json:"partition"`

	Raw json.RawMessage `json:"-"`
}

// Category represents a BCM node category. Nodes assigned to a category
// inherit its BMCSettings unless they set their own.
type Category struct {
	UUID        string       `json:"uuid"`
	Name        string       `json:"name"`
	BMCSettings *BMCSettings `json:"bmcSettings"`
}

// Partition represents a BCM partition (top-level container). Nodes inherit
// its BMCSettings unless overridden at the category or device level.
type Partition struct {
	UUID        string       `json:"uuid"`
	Name        string       `json:"name"`
	BMCSettings *BMCSettings `json:"bmcSettings"`
}

// UpdateResponse is the response from cmdevice.updateDevice.
type UpdateResponse struct {
	Success    bool         `json:"success"`
	TaskUUID   string       `json:"task_uuid"`
	Validation []Validation `json:"validation"`
}

// Validation represents a single BCM field validation error.
type Validation struct {
	ErrorCode string `json:"error_code"`
	Field     string `json:"field"`
	Message   string `json:"message"`
	Severity  string `json:"severity"`
}

// versionResponse is the response from GET /rest/v1/version.
type versionResponse struct {
	CMVersion       string `json:"cm_version"`
	CMDVersion      string `json:"cmd_version"`
	BuildHash       string `json:"build_hash"`
	BuildIndex      int    `json:"build_index"`
	DatabaseVersion int    `json:"database_version"`
}

// errorResponse captures error messages from the BCM JSON API.
type errorResponse struct {
	ErrorMessage string `json:"errormessage"`
}
