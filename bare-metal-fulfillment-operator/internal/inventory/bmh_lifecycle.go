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

	"github.com/osac-project/osac/bare-metal-fulfillment-operator/internal/baremetalhost"
)

// BMHLifecycleManager abstracts BareMetalHost CR operations for inventory
// backends that prepare or release Metal3-managed hosts. Satisfied by
// *baremetalhost.Manager.
type BMHLifecycleManager interface {
	CreateBMH(ctx context.Context, params baremetalhost.CreateParams) error
	DeleteBMH(ctx context.Context, name string) error
	BMHExists(ctx context.Context, name string) (bool, error)
	IsBMHReady(ctx context.Context, name string) (bool, error)
	EnsureBMCSecret(ctx context.Context, name, username, password string) error
	DeleteBMCSecret(ctx context.Context, name string) error
	GetHardwareNICs(ctx context.Context, name string) ([]string, error)
	Namespace() string
}
