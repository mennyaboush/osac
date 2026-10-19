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
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/osac-project/osac/bare-metal-fulfillment-operator/internal/baremetalhost"
	"github.com/osac-project/osac/bare-metal-fulfillment-operator/internal/netboxclient"
	"github.com/osac-project/osac/bare-metal-fulfillment-operator/internal/shared"
	privatev1 "github.com/osac-project/osac/proto/gen/osac/private/v1"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/oauth"
	experimentalcredentials "google.golang.org/grpc/experimental/credentials"
)

const netBoxHostClass = "metal3"

var errNetBoxClientNotImplemented = errors.New("NetBox inventory client is not implemented")

const secretAPIHTTPTimeout = 30 * time.Second

// NetBoxSecretAPIConfig contains the endpoint and mounted OAuth client credentials.
type NetBoxSecretAPIConfig struct {
	URL              string
	IssuerURL        string
	ClientIDFile     string
	ClientSecretFile string
	CAFile           string
}

func (c NetBoxSecretAPIConfig) validate() error {
	if c.URL == "" || c.IssuerURL == "" || c.ClientIDFile == "" || c.ClientSecretFile == "" {
		return errors.New("secret API endpoint, issuer, and client credential files are required")
	}
	return nil
}

// NetBoxSecretAPIClient is the authenticated private Secrets gRPC client used by NetBox.
type NetBoxSecretAPIClient struct {
	privatev1.SecretsClient
	conn *grpc.ClientConn
}

// NewNetBoxSecretAPIClient creates a TLS gRPC client authenticated with Keycloak.
func NewNetBoxSecretAPIClient(config NetBoxSecretAPIConfig) (*NetBoxSecretAPIClient, error) {
	conn, err := newNetBoxSecretAPIConn(config)
	if err != nil {
		return nil, err
	}
	return &NetBoxSecretAPIClient{SecretsClient: privatev1.NewSecretsClient(conn), conn: conn}, nil
}

// Close releases the gRPC connection owned by the Secret API client.
func (c *NetBoxSecretAPIClient) Close() error {
	if c == nil || c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

func newNetBoxSecretAPIConn(config NetBoxSecretAPIConfig) (*grpc.ClientConn, error) {
	tlsConfig, err := netBoxSecretAPITLSConfig(config)
	if err != nil {
		return nil, err
	}
	return newNetBoxSecretAPIConnWithTLS(config, tlsConfig)
}

func netBoxSecretAPITLSConfig(config NetBoxSecretAPIConfig) (*tls.Config, error) {
	if err := config.validate(); err != nil {
		return nil, err
	}
	return netboxclient.NewTLSConfig(config.CAFile)
}

func newNetBoxSecretAPIConnWithTLS(config NetBoxSecretAPIConfig, tlsConfig *tls.Config) (*grpc.ClientConn, error) {
	tokenSource, err := newNetBoxSecretAPITokenSource(config, tlsConfig)
	if err != nil {
		return nil, err
	}
	return dialNetBoxSecretAPI(config.URL, tlsConfig, tokenSource)
}

func newNetBoxSecretAPITokenSource(config NetBoxSecretAPIConfig, tlsConfig *tls.Config) (oauth2.TokenSource, error) {
	clientID, idErr := readNetBoxSecretAPIFile(config.ClientIDFile, "client ID")
	clientSecret, secretErr := readNetBoxSecretAPIFile(config.ClientSecretFile, "client secret")
	if err := errors.Join(idErr, secretErr); err != nil {
		return nil, err
	}
	return netBoxSecretAPITokenSource(clientID, clientSecret, config.IssuerURL, tlsConfig), nil
}

func netBoxSecretAPITokenSource(clientID, clientSecret, issuerURL string, tlsConfig *tls.Config) oauth2.TokenSource {
	tokenContext := context.WithValue(context.Background(), oauth2.HTTPClient, newNetBoxSecretAPIHTTPClient(tlsConfig))
	credentials := &clientcredentials.Config{
		ClientID: clientID, ClientSecret: clientSecret,
		TokenURL:  strings.TrimRight(issuerURL, "/") + "/protocol/openid-connect/token",
		AuthStyle: oauth2.AuthStyleInHeader,
	}
	return credentials.TokenSource(tokenContext)
}

func newNetBoxSecretAPIHTTPClient(tlsConfig *tls.Config) *http.Client {
	return &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyFromEnvironment, TLSClientConfig: tlsConfig.Clone()},
		Timeout:   secretAPIHTTPTimeout,
	}
}

func dialNetBoxSecretAPI(endpoint string, tlsConfig *tls.Config, tokenSource oauth2.TokenSource) (*grpc.ClientConn, error) {
	target, err := netBoxSecretAPITarget(endpoint)
	if err != nil {
		return nil, err
	}
	return newNetBoxSecretAPIClientConn(target, tlsConfig, tokenSource)
}

func newNetBoxSecretAPIClientConn(target string, tlsConfig *tls.Config, tokenSource oauth2.TokenSource) (*grpc.ClientConn, error) {
	conn, err := grpc.NewClient(target, netBoxSecretAPIDialOptions(tlsConfig, tokenSource)...)
	if err != nil {
		return nil, fmt.Errorf("create Secret API gRPC client: %w", err)
	}
	return conn, nil
}

func netBoxSecretAPIDialOptions(tlsConfig *tls.Config, tokenSource oauth2.TokenSource) []grpc.DialOption {
	return []grpc.DialOption{
		grpc.WithTransportCredentials(experimentalcredentials.NewTLSWithALPNDisabled(tlsConfig.Clone())),
		grpc.WithPerRPCCredentials(oauth.TokenSource{TokenSource: tokenSource}),
	}
}

func readNetBoxSecretAPIFile(path, credential string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read Secret API %s: %w", credential, err)
	}
	return strings.TrimSpace(string(data)), nil
}

func netBoxSecretAPITarget(endpoint string) (string, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Host == "" {
		return "", errors.New("secret API URL must include a host")
	}
	return parsed.Host, nil
}

// NetBoxAPI defines the operations needed by the inventory adapter. It is
// satisfied by netboxclient.Client and keeps generated SDK calls behind a
// consumer-side interface.
type NetBoxAPI interface {
	ForEachDevice(ctx context.Context, query netboxclient.DeviceQuery, visit func(netboxclient.Device) (bool, error)) error
	ForEachDeviceCustomField(ctx context.Context, visit func(netboxclient.CustomField) (bool, error)) error
	GetDevice(ctx context.Context, id string) (netboxclient.DeviceSnapshot, error)
	PatchDevice(ctx context.Context, id string, patch netboxclient.DevicePatch, etag string) (netboxclient.DeviceSnapshot, error)
}

// NetBoxClientConfig contains the mounted-file and endpoint settings for NetBox.
type NetBoxClientConfig struct {
	URL               string `json:"url"`
	TokenFile         string `json:"tokenFile"`
	CAFile            string `json:"caFile"`
	AllowInsecureHTTP bool   `json:"allowInsecureHTTP"`
}

// ParseNetBoxOptions extracts the NetBox-specific settings from inventory
// configuration. The token value itself must remain in the mounted file.
func ParseNetBoxOptions(options map[string]any) (*NetBoxClientConfig, error) {
	netBoxOptions, ok := options["netbox"]
	if !ok {
		return nil, fmt.Errorf("netbox options not found in config")
	}

	raw, err := json.Marshal(netBoxOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to parse netbox options")
	}

	var config NetBoxClientConfig
	if err := json.Unmarshal(raw, &config); err != nil {
		return nil, fmt.Errorf("failed to parse netbox options")
	}
	if config.URL == "" {
		return nil, fmt.Errorf("netbox url is required in config")
	}
	if config.TokenFile == "" {
		return nil, fmt.Errorf("netbox tokenFile is required in config")
	}
	return &config, nil
}

// NetBoxClient implements inventory.Client. The secure API boundary is
// available for the follow-on allocation and release operations.
type NetBoxClient struct {
	api        NetBoxAPI
	bmhManager baremetalhost.BMHLifecycleManager
	hostClass  string
	secretAPI  *NetBoxSecretAPIClient
}

var (
	_ Client = (*NetBoxClient)(nil)
)

// NewNetBoxAPI constructs the secure NetBox API dependency from mounted configuration.
func NewNetBoxAPI(config *Config) (NetBoxAPI, error) {
	if config == nil {
		return nil, fmt.Errorf("netbox inventory config is required")
	}
	netBoxConfig, err := ParseNetBoxOptions(config.Options)
	if err != nil {
		return nil, err
	}

	api, err := netboxclient.New(netboxclient.Config{
		Endpoint:          netBoxConfig.URL,
		TokenFile:         netBoxConfig.TokenFile,
		CAFile:            netBoxConfig.CAFile,
		AllowInsecureHTTP: netBoxConfig.AllowInsecureHTTP,
	})
	if err != nil {
		return nil, err
	}
	return api, nil
}

// NewNetBoxClient creates a NetBox inventory client with injected dependencies.
func NewNetBoxClient(api NetBoxAPI, bmhManager baremetalhost.BMHLifecycleManager, hostClass string, secretAPI *NetBoxSecretAPIClient) *NetBoxClient {
	return &NetBoxClient{
		api:        api,
		bmhManager: bmhManager,
		hostClass:  hostClass,
		secretAPI:  secretAPI,
	}
}

// Close releases connections owned by the inventory client.
func (c *NetBoxClient) Close() error {
	if c.secretAPI == nil {
		return nil
	}
	return c.secretAPI.Close()
}

func (c *NetBoxClient) FindFreeHost(ctx context.Context, selector map[string]string) (*Host, error) {
	return c.findFreeHost(ctx, buildFreeHostQuery(selector))
}

func (c *NetBoxClient) findFreeHost(ctx context.Context, query netboxclient.DeviceQuery) (*Host, error) {
	namespace, err := c.metal3Namespace()
	if err != nil {
		return nil, err
	}

	var foundHost *Host
	err = c.api.ForEachDevice(ctx, query, func(device netboxclient.Device) (bool, error) {
		foundHost = netboxHostFromDevice(namespace, c.hostClass, device)
		return false, nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to search NetBox for a free host: %w", err)
	}
	return foundHost, nil
}

func (c *NetBoxClient) metal3Namespace() (string, error) {
	if c.bmhManager != nil {
		if namespace := c.bmhManager.Namespace(); namespace != "" {
			return namespace, nil
		}
	}
	return "", errors.New("NetBox inventory requires a Metal3 namespace")
}

func netboxHostFromDevice(namespace, hostClass string, device netboxclient.Device) *Host {
	name := "netbox-" + device.ID
	return &Host{
		InventoryHostID: fmt.Sprintf("%s/%s", namespace, name),
		Name:            name,
		HostClass:       hostClass,
		ProvisionState:  shared.OsacDefaultProvisionStateValue,
		ManagedBy:       shared.OsacDefaultManagedByValue,
		Ready:           true,
	}
}

func buildFreeHostQuery(selector map[string]string) netboxclient.DeviceQuery {
	capabilityFilters := make(netboxclient.DeviceQuery, len(selector))
	for key, value := range selector {
		capabilityFilters["cf_"+key] = value
	}
	commonSelectors := netboxclient.DeviceQuery{
		"status":                     "staged",
		"cf_osac_managed":            "true",
		"cf_osac_instance_id__empty": "true",
	}
	query := make(netboxclient.DeviceQuery, len(capabilityFilters)+len(commonSelectors))
	maps.Copy(query, capabilityFilters)
	maps.Copy(query, commonSelectors)
	return query
}

func (*NetBoxClient) AssignHost(_ context.Context, _ string, _ string, _ map[string]string) (*Host, error) {
	return nil, errNetBoxClientNotImplemented
}

func (*NetBoxClient) UnassignHost(_ context.Context, _ string, _ []string) error {
	return errNetBoxClientNotImplemented
}

func (*NetBoxClient) GetHostNICs(_ context.Context, _ string) ([]HostNIC, error) {
	return nil, errNetBoxClientNotImplemented
}

// GetHostLogicalPortMACs is not implemented until NetBox inventory operations are added.
func (*NetBoxClient) GetHostLogicalPortMACs(_ context.Context, _ string) (map[string]string, error) {
	return nil, errNetBoxClientNotImplemented
}
