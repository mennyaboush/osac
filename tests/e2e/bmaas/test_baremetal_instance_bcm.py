"""BCM-backend E2E smoke test (OSAC-3773 / OSAC-3775).

Runs only when the E2E environment configured the BCM inventory backend (the
`bcm_simulator_url` fixture skips otherwise). The generic BMH lifecycle is
already covered by `test_baremetal_instance_lifecycle` against any backend; this
test adds the BCM-specific assertions the generic test cannot make — that the
assigned host is marked in BCM with `osac_instance_id` and no tenant-identifying
data, and that deleting the instance releases the host back to the BCM pool.

It talks to the BCM simulator's admin control plane (`/_admin/devices`), which
reflects exactly what the operator wrote to BCM via `cmdevice.updateDevice`.
"""

from __future__ import annotations

import json
import logging
import ssl
from typing import Any
from urllib.request import urlopen

import pytest

from tests.core.grpc_client import GRPCClient
from tests.core.helpers import (
    wait_for_bmh_available,
    wait_for_bmh_provisioned,
    wait_for_bmi_cr,
    wait_for_bmi_deletion,
    wait_for_bmi_grpc_removal,
    wait_for_bmi_running,
)
from tests.core.k8s_client import K8sClient
from tests.core.osac_cli import OsacCLI

logger = logging.getLogger(__name__)

# extra_values keys the operator is allowed to write on a BCM device. Anything
# else — and in particular anything tenant-identifying — must not be present.
_ALLOWED_EXTRA_VALUE_KEYS: frozenset[str] = frozenset({"resource_class", "osac_instance_id", "osac_bmc_address"})

# Insecure TLS: the simulator serves a self-signed cert and the operator itself
# connects with insecureSkipVerify — the test mirrors that.
_INSECURE_TLS = ssl.create_default_context()
_INSECURE_TLS.check_hostname = False
_INSECURE_TLS.verify_mode = ssl.CERT_NONE


def _bcm_devices(base_url: str) -> list[dict[str, Any]]:
    with urlopen(f"{base_url}/_admin/devices", timeout=10, context=_INSECURE_TLS) as resp:
        return json.load(resp)


def _device(base_url: str, hostname: str) -> dict[str, Any] | None:
    return next((d for d in _bcm_devices(base_url) if d.get("hostname") == hostname), None)


@pytest.mark.sanity
def test_baremetal_instance_bcm_host_release(
    cli: OsacCLI,
    grpc: GRPCClient,
    k8s_hub_client: K8sClient,
    catalog_item: str,
    bmh_namespace: str,
    test_run_id: str,
    ssh_public_key: str,
    bcm_simulator_url: str,
) -> None:
    name = f"e2e-bcm-{test_run_id}"
    bmi_id: str = cli.create_baremetal_instance(name=name, catalog_item=catalog_item, ssh_key=ssh_public_key)
    bmh_ns = ""
    bmh_name = ""

    try:
        assert bmi_id in grpc.list_baremetal_instance_ids()

        bmi_cr_name: str = wait_for_bmi_cr(k8s=k8s_hub_client, uuid=bmi_id)
        wait_for_bmi_running(grpc=grpc, bmi_id=bmi_id)

        external_host_id: str = k8s_hub_client.get_baremetal_instance_external_host_id(name=bmi_cr_name)
        assert "/" in external_host_id, f"Expected namespace/name format, got: {external_host_id}"
        bmh_ns, bmh_name = external_host_id.split("/", 1)
        assert bmh_ns == bmh_namespace, f"BMH landed in {bmh_ns}, expected {bmh_namespace}"

        # The operator created a BMH from the BCM LiteNode and Ironic provisioned it.
        wait_for_bmh_provisioned(k8s=k8s_hub_client, name=bmh_name, bmh_namespace=bmh_ns)
        consumer_ref: str = k8s_hub_client.get_bmh_consumer_ref(name=bmh_name, bmh_namespace=bmh_ns)
        assert consumer_ref != "", f"BMH {bmh_name} has no consumerRef after allocation"

        # BCM-specific: correlate to THIS instance's host. The operator names the
        # BMH after the BCM LiteNode hostname (inventory/bcm.go: Host.Name =
        # device.Hostname), so bmh_name is the BCM device to inspect. Correlating by
        # host keeps the assertions correct even when other bmaas tests run in
        # parallel against the same shared simulator.
        device = _device(bcm_simulator_url, bmh_name)
        assert device is not None, f"BCM device {bmh_name} not found in simulator"
        extra_values: dict[str, Any] = device.get("extra_values", {})
        assert extra_values.get("osac_instance_id"), f"BCM host {bmh_name} missing osac_instance_id after assignment"

        # No tenant-identifying data leaked into BCM (OSAC-3775 AC#7): the only keys
        # allowed are resource_class / osac_instance_id / osac_bmc_address, and the
        # instance name must not appear anywhere in extra_values.
        unexpected_keys = set(extra_values) - _ALLOWED_EXTRA_VALUE_KEYS
        assert not unexpected_keys, f"unexpected extra_values keys in BCM (possible data leak): {unexpected_keys}"
        assert name.lower() not in json.dumps(extra_values).lower(), (
            f"instance name leaked into BCM extra_values: {extra_values}"
        )

        # Deprovision -> host released back to the BCM pool.
        cli.delete_baremetal_instance(uuid=bmi_id)
        wait_for_bmi_deletion(k8s=k8s_hub_client, name=bmi_cr_name)
        wait_for_bmi_grpc_removal(grpc=grpc, uuid=bmi_id)
        wait_for_bmh_available(k8s=k8s_hub_client, name=bmh_name, bmh_namespace=bmh_ns)

        # BCM-specific: the host is released (still present, osac_instance_id cleared)
        # so it can be re-assigned from the pool.
        released = _device(bcm_simulator_url, bmh_name)
        assert released is not None, f"BCM device {bmh_name} vanished; expected it released, not removed"
        assert not released.get("extra_values", {}).get("osac_instance_id"), (
            f"BCM host {bmh_name} still marked assigned after deletion"
        )
    except BaseException:
        bmi_cr: str = k8s_hub_client.get_baremetal_instance_name(uuid=bmi_id, checked=False)
        if bmi_cr:
            try:
                cli.delete_baremetal_instance(uuid=bmi_id)
                wait_for_bmi_deletion(k8s=k8s_hub_client, name=bmi_cr)
                wait_for_bmi_grpc_removal(grpc=grpc, uuid=bmi_id)
                if bmh_name:
                    wait_for_bmh_available(k8s=k8s_hub_client, name=bmh_name, bmh_namespace=bmh_ns)
            except Exception:
                logger.exception("Failed to clean up BMI %s", bmi_id)
        raise
