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

// Device represents a BCM device with typed access to OSAC-relevant
// fields plus the raw JSON needed for full-object update round-trips.
type Device struct {
	BaseType    string         `json:"baseType"`
	ChildType   string         `json:"childType"`
	UUID        string         `json:"uuid"`
	Hostname    string         `json:"hostname"`
	MAC         string         `json:"mac"`
	ExtraValues map[string]any `json:"extra_values"`

	Raw json.RawMessage `json:"-"`
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
