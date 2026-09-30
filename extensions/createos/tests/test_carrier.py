import asyncio
import json
from dataclasses import replace
from pathlib import Path
from uuid import uuid4

import httpx
import pytest
from ufo_ext_createos.carrier import (
    MAX_REQUEST_BYTES,
    CreateOSCarrier,
    SandboxView,
    manifest,
    owner_key,
    proxy_rules,
    sandbox_name,
)

from ufo.config import BlobConfig, Config, DatabaseConfig, SandboxConfig
from ufo.harness.sandbox.select import select_carriers
from ufo.sdk.sandbox import ProxyEndpoint, SandboxHandle, SandboxSpec, SandboxUnreachable


def spec() -> SandboxSpec:
    return SandboxSpec(
        conversation_id=uuid4(),
        image_ref="tpl_example",
        workspace_host_path="/unused",
        proxy=ProxyEndpoint(port=443, ca_cert="ca", public_url="https://egress.example.com"),
        run_token="turn-token",
        turn_id=uuid4(),
    )


def test_names_fit_provider_limit_and_ownership_uses_full_uuid() -> None:
    conversation = uuid4()
    assert len(sandbox_name(conversation)) == 22
    assert sandbox_name(conversation) == sandbox_name(conversation)
    assert sandbox_name(conversation) != sandbox_name(uuid4())
    assert owner_key(conversation) == f"UFO_CONVERSATION_{conversation.hex}"


def test_proxy_rules_are_exact_public_addresses_and_port() -> None:
    assert proxy_rules(("8.8.8.8", "1.1.1.1", "8.8.8.8"), 8443) == (
        "1.1.1.1:8443",
        "8.8.8.8:8443",
    )


@pytest.mark.parametrize("addresses", [(), ("127.0.0.1",), ("10.0.0.1",), ("::1",)])
def test_proxy_rules_never_turn_an_empty_or_private_destination_into_open_egress(
    addresses: tuple[str, ...],
) -> None:
    with pytest.raises(ValueError):
        proxy_rules(addresses, 443)


def test_manifest_resolves_carrier_and_requires_public_proxy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("UFO_CREATEOS_API_KEY", "test-key")
    config = Config(
        database=DatabaseConfig(url="sqlite+aiosqlite:///carrier.db"),
        blob=BlobConfig(backend="filesystem", root=Path("blobs")),
        sandbox=SandboxConfig(backend="createos", proxy_public_url="https://egress.example.com"),
    )
    selected = select_carriers(config, (manifest(),))
    assert isinstance(selected.carrier, CreateOSCarrier)
    assert selected.spec.off_cluster
    config.sandbox.proxy_public_url = None
    with pytest.raises(RuntimeError, match="proxy_public_url"):
        select_carriers(config, (manifest(),))


def test_missing_key_fails_at_carrier_construction(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("UFO_CREATEOS_API_KEY", raising=False)
    monkeypatch.delenv("CREATEOS_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="CREATEOS_API_KEY"):
        CreateOSCarrier.from_env()


def test_sandbox_ownership_rejects_a_matching_name_with_another_marker() -> None:
    request = spec()
    sandbox = SandboxView(
        id="sb-owned", name=sandbox_name(request.conversation_id), status="running", envs=[]
    )
    with pytest.raises(SandboxUnreachable, match="another conversation"):
        CreateOSCarrier._check_owner(sandbox, request.conversation_id)
    owned = sandbox.model_copy(update={"envs": [owner_key(request.conversation_id)]})
    CreateOSCarrier._check_owner(owned, request.conversation_id)


async def test_attach_paginates_skips_destroyed_names_and_carries_no_credentials() -> None:
    request = spec()
    name = sandbox_name(request.conversation_id)
    owned = {
        "id": "sb-owned",
        "name": name,
        "status": "running",
        "envs": [owner_key(request.conversation_id)],
    }

    def response(call: httpx.Request) -> httpx.Response:
        if call.url.path == "/v1/sandboxes/sb-owned":
            data = owned
        elif call.url.params.get("offset") == "1":
            data = {"data": [owned], "pagination": {"total": 2}}
        else:
            data = {
                "data": [{**owned, "id": "sb-old", "status": "destroyed"}],
                "pagination": {"total": 2},
            }
        return httpx.Response(200, json={"status": "success", "data": data})

    carrier = CreateOSCarrier(api_key="test-key", _transport=httpx.MockTransport(response))
    handle = await carrier.attach(request)
    assert handle is not None and handle.container_id == "sb-owned"
    assert handle.run_token is None and not handle.egress_env


async def test_read_only_attach_does_not_replace_a_missing_sandbox() -> None:
    request = replace(spec(), resume_id="sb-missing")
    carrier = CreateOSCarrier(
        api_key="test-key",
        _transport=httpx.MockTransport(lambda _: httpx.Response(404)),
    )
    assert await carrier.attach(request) is None


async def test_readiness_resumes_paused_sandbox_and_handles_concurrent_resume() -> None:
    states = iter(["paused", "resuming", "running"])

    def response(call: httpx.Request) -> httpx.Response:
        if call.method == "POST":
            return httpx.Response(409)
        return httpx.Response(
            200, json={"status": "success", "data": {"id": "sb-test", "status": next(states)}}
        )

    carrier = CreateOSCarrier(api_key="test-key", _transport=httpx.MockTransport(response))
    assert (await carrier._ready("sb-test")).status == "running"


@pytest.mark.parametrize("old_status", [None, "destroying", "destroyed", "failed"])
@pytest.mark.parametrize("recovery", ["create", "existing", "conflict"])
async def test_expired_handle_recovers_one_conversation_sandbox(
    old_status: str | None, recovery: str
) -> None:
    request = replace(
        spec(),
        resume_id="sb-expired",
        proxy=ProxyEndpoint(port=443, ca_cert="ca", public_url="https://1.1.1.1"),
    )
    owned = {
        "id": "sb-replacement",
        "name": sandbox_name(request.conversation_id),
        "status": "running",
        "envs": [owner_key(request.conversation_id)],
    }
    available = recovery == "existing"
    creates = 0
    old_reads = 0

    def response(call: httpx.Request) -> httpx.Response:
        nonlocal available, creates, old_reads
        match call.method, call.url.path:
            case "GET", "/v1/sandboxes/sb-expired":
                old_reads += 1
                if old_status is None:
                    return httpx.Response(404)
                state = "destroyed" if old_status == "destroying" and old_reads > 1 else old_status
                data = {**owned, "id": "sb-expired", "status": state}
            case "GET", "/v1/sandboxes":
                page = [owned] if available else []
                data = {"data": page, "pagination": {"total": len(page)}}
            case "POST", "/v1/sandboxes":
                creates += 1
                available = True
                assert json.loads(call.content)["name"] == owned["name"]
                if recovery == "conflict":
                    return httpx.Response(409)
                data = owned
            case "POST", "/v1/sandboxes/sb-replacement/exec":
                data = {"result": {"stdout": "{}", "stderr": "", "exit_code": 0}}
            case _:
                assert call.url.path.startswith("/v1/sandboxes/sb-replacement")
                data = owned
        return httpx.Response(200, json={"status": "success", "data": data})

    carrier = CreateOSCarrier(api_key="test-key", _transport=httpx.MockTransport(response))
    first = await carrier.create(request)
    recovered = await carrier.create(request)
    persisted = await carrier.create(replace(request, resume_id=first.container_id))
    assert first.container_id == recovered.container_id == persisted.container_id == owned["id"]
    assert creates == (0 if recovery == "existing" else 1)


@pytest.mark.parametrize("status", [401, 403, 500])
async def test_provider_failure_does_not_replace_saved_sandbox(status: int) -> None:
    carrier = CreateOSCarrier(
        api_key="test-key", _transport=httpx.MockTransport(lambda _: httpx.Response(status))
    )
    with pytest.raises(RuntimeError, match=f"HTTP {status}"):
        await carrier.create(replace(spec(), resume_id="sb-owned"))


async def test_provider_errors_do_not_expose_response_or_api_key() -> None:
    carrier = CreateOSCarrier(
        api_key="test-secret",
        _transport=httpx.MockTransport(lambda _: httpx.Response(503, text="test-secret")),
    )
    with pytest.raises(RuntimeError) as raised:
        await carrier._get("sb-test")
    assert "test-secret" not in str(raised.value)
    assert "test-secret" not in repr(carrier)


async def test_guest_filesystem_error_retains_errno() -> None:
    body = {
        "stdout": json.dumps({"error": "permission denied", "errno": 13}),
        "stderr": "",
        "exit_code": 0,
    }
    carrier = CreateOSCarrier(
        api_key="test-key",
        _transport=httpx.MockTransport(
            lambda _: httpx.Response(200, json={"status": "success", "data": {"result": body}})
        ),
    )
    with pytest.raises(PermissionError):
        await carrier._guest("sb-test", {"action": "read", "path": "/etc/shadow"})


async def test_create_recovers_name_conflict_and_refreshes_turn_environment() -> None:
    request = replace(
        spec(),
        proxy=ProxyEndpoint(port=443, ca_cert="ca", public_url="https://1.1.1.1"),
        env={"GH_TOKEN": "first-grant"},
    )
    owned = {
        "id": "sb-owned",
        "name": sandbox_name(request.conversation_id),
        "status": "running",
        "envs": [owner_key(request.conversation_id)],
    }
    listing = iter([[], [owned]])

    def response(call: httpx.Request) -> httpx.Response:
        match call.method, call.url.path:
            case "GET", "/v1/sandboxes":
                page = next(listing)
                data = {"data": page, "pagination": {"total": len(page)}}
            case "POST", "/v1/sandboxes":
                body = json.loads(call.content)
                if body["egress"] != ["1.1.1.1:443"] or body["ingress_enabled"]:
                    return httpx.Response(400)
                if body["envs"] != {owner_key(request.conversation_id): "1"}:
                    return httpx.Response(400)
                return httpx.Response(409)
            case "POST", "/v1/sandboxes/sb-owned/exec":
                data = {"result": {"stdout": "{}", "stderr": "", "exit_code": 0}}
            case _:
                data = owned
        return httpx.Response(200, json={"status": "success", "data": data})

    carrier = CreateOSCarrier(api_key="test-key", _transport=httpx.MockTransport(response))
    first = await carrier.create(request)
    second = await carrier.create(
        replace(request, resume_id=first.container_id, run_token="next", env={})
    )
    assert first.container_id == second.container_id == "sb-owned"
    assert first.egress_env["GH_TOKEN"] == "first-grant"
    assert "GH_TOKEN" not in second.egress_env
    assert second.egress_env["HTTPS_PROXY"].startswith("https://next:")
    assert "test-key" not in json.dumps(dict(second.egress_env))


@pytest.mark.parametrize("final_state", ["running", "error"])
async def test_provider_error_gets_one_fresh_resume_attempt(final_state: str) -> None:
    states = iter(["error", final_state])

    def response(call: httpx.Request) -> httpx.Response:
        state = next(states) if call.method == "GET" else "resuming"
        return httpx.Response(
            200, json={"status": "success", "data": {"id": "sb-test", "status": state}}
        )

    carrier = CreateOSCarrier(api_key="test-key", _transport=httpx.MockTransport(response))
    if final_state == "running":
        assert (await carrier._ready("sb-test")).status == "running"
    else:
        with pytest.raises(RuntimeError, match="failed to resume"):
            await carrier._ready("sb-test")


@pytest.mark.parametrize("action", ["stage", "exec"])
async def test_missing_guest_results_fail_instead_of_using_default_paths(action: str) -> None:
    carrier = CreateOSCarrier(
        api_key="test-key",
        _transport=httpx.MockTransport(
            lambda _: httpx.Response(
                200,
                json={
                    "status": "success",
                    "data": {"result": {"stdout": "{}", "stderr": "", "exit_code": 0}},
                },
            )
        ),
    )
    with pytest.raises(RuntimeError):
        await carrier._guest("sb-test", {"action": action, "path": "/var/lib/ufo-carrier/test"})


async def test_oversized_api_payload_is_rejected_before_network_access() -> None:
    carrier = CreateOSCarrier(api_key="test-key")
    with pytest.raises(ValueError, match="256 KiB"):
        await carrier._request("POST", "/v1/sandboxes", {"name": "x" * MAX_REQUEST_BYTES})


@pytest.mark.parametrize(
    "url", ["http://example.com", "https://user:pass@example.com", "https://example.com/path"]
)
def test_api_origin_rejects_unencrypted_or_credential_bearing_urls(url: str) -> None:
    with pytest.raises(ValueError, match="HTTPS origin"):
        CreateOSCarrier(api_key="test-key", base_url=url)


async def test_preemption_abandons_output_without_stopping_remote_command() -> None:
    started = asyncio.Event()
    abandoned = asyncio.Event()
    stage = f"/var/lib/ufo-carrier/{uuid4().hex}"

    async def response(call: httpx.Request) -> httpx.Response:
        payload = json.loads(json.loads(call.content)["stdin"])
        match payload["action"]:
            case "stage":
                result = {"path": stage}
            case "exec":
                started.set()
                await asyncio.Future()
                raise AssertionError("command cannot complete")
            case "abandon":
                abandoned.set()
                result = {}
            case _:
                raise AssertionError("preemption must not stop or remove the active command")
        return httpx.Response(
            200,
            json={
                "status": "success",
                "data": {"result": {"stdout": json.dumps(result), "stderr": "", "exit_code": 0}},
            },
        )

    carrier = CreateOSCarrier(api_key="test-key", _transport=httpx.MockTransport(response))
    handle = SandboxHandle(conversation_id=uuid4(), container_id="sb-owned", turn_id=uuid4())
    task = asyncio.create_task(carrier.exec(handle, ("sleep", "30"), 60))
    await asyncio.wait_for(started.wait(), 5)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert abandoned.is_set()
