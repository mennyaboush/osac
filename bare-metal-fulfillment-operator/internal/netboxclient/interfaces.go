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
	"net/http"
	"strconv"

	netbox "github.com/netbox-community/go-netbox/v4"
)

// DeviceInterface contains the native interface fields used for logical MAC lookup.
type DeviceInterface struct {
	ID           string
	Name         string
	PrimaryMAC   string
	CustomFields map[string]interface{}
}

// ForEachDeviceInterface visits interfaces for a saved device ID in NetBox order.
// The visitor returns true to continue or false to stop successfully.
func (c *Client) ForEachDeviceInterface(
	ctx context.Context,
	deviceID string,
	visit func(DeviceInterface) (bool, error),
) error {
	if visit == nil {
		return &APIError{Kind: ErrorKindInvalidRequest}
	}
	numericID, err := parseDeviceID(deviceID)
	if err != nil {
		return err
	}

	return forEachPaginatedResult(ctx, func(pageCtx context.Context, offset int32) (pageData[netbox.Interface], error) {
		page, response, err := c.listDeviceInterfacePage(pageCtx, numericID, offset)
		if err != nil {
			return pageData[netbox.Interface]{}, err
		}
		if page == nil || response == nil || page.Results == nil {
			return pageData[netbox.Interface]{}, &APIError{Kind: ErrorKindInvalidResponse}
		}

		return pageData[netbox.Interface]{
			count:   page.Count,
			hasNext: page.GetNext() != "",
			results: page.Results,
		}, nil
	}, func(value netbox.Interface) (bool, error) {
		interfaceValue, err := fromSDKDeviceInterface(value, numericID)
		if err != nil {
			return false, err
		}
		return visit(interfaceValue)
	})
}

func (c *Client) listDeviceInterfacePage(
	ctx context.Context,
	deviceID int32,
	offset int32,
) (*netbox.PaginatedInterfaceList, *http.Response, error) {
	return retryGET(ctx, func(requestContext context.Context) (*netbox.PaginatedInterfaceList, *http.Response, error) {
		return c.api.DcimAPI.DcimInterfacesList(requestContext).
			DeviceId([]int32{deviceID}).
			Limit(defaultPageSize).
			Offset(offset).
			Execute()
	})
}

func fromSDKDeviceInterface(value netbox.Interface, requestedDeviceID int32) (DeviceInterface, error) {
	if value.Id <= 0 || value.Device.Id <= 0 || value.Device.Id != requestedDeviceID {
		return DeviceInterface{}, &APIError{Kind: ErrorKindInvalidResponse}
	}

	primaryMAC := ""
	if primary := value.PrimaryMacAddress.Get(); primary != nil {
		primaryMAC = primary.GetMacAddress()
		if primaryMAC == "" {
			return DeviceInterface{}, &APIError{Kind: ErrorKindInvalidResponse}
		}
	}

	return DeviceInterface{
		ID:           strconv.FormatInt(int64(value.Id), 10),
		Name:         value.GetName(),
		PrimaryMAC:   primaryMAC,
		CustomFields: cloneCustomFields(value.CustomFields),
	}, nil
}
