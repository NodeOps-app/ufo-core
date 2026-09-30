"""Persistent CreateOS sandboxes with private ingress and proxy-only egress."""

import asyncio
import hashlib
import ipaddress
import json
import socket
from collections.abc import AsyncIterator, Mapping
from dataclasses import dataclass, field, replace
from functools import cached_property
from pathlib import Path
from typing import Literal
from urllib.parse import quote, urlsplit
from uuid import UUID, uuid4

import httpx
from pydantic import BaseModel, Field

from ufo.sdk.credentials import deploy_env
from ufo.sdk.manifest import Manifest
from ufo.sdk.sandbox import (
    SANDBOX_ENV,
    CarrierSpec,
    DialTarget,
    ExecResult,
    SandboxHandle,
    SandboxProviderUnavailable,
    SandboxSpec,
    SandboxUnreachable,
    egress_proxy_env,
    sandbox_runtime_root,
    ufo_fs_file_op,
)
from ufo_ext_createos.tunnel import CreateOSTunnels

NAME = "createos"
API_KEY_ENV = "CREATEOS_API_KEY"
API_URL = "https://api.sb.createos.sh"
DEFAULT_SHAPE = "s-2vcpu-2gb"
CONTROL_TIMEOUT_SECONDS = 120
LIFECYCLE_TIMEOUT_SECONDS = 180
STATE_POLL_SECONDS = 1
IDLE_TIMEOUT_SECONDS = 1800
READ_CHUNK_BYTES = 1024 * 1024
MAX_REQUEST_BYTES = 256 * 1024
MAX_FILE_BYTES = 10 * 1024 * 1024 * 1024
PAGE_SIZE = 500
NAME_DIGEST_CHARS = 18
TERMINAL_STATES = frozenset({"destroying", "destroyed", "failed"})
GUEST_SOURCE = Path(__file__).with_name("guest.py").read_text()
GUEST_ENV = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/home/user", **SANDBOX_ENV}


class Envelope[T](BaseModel):
    status: Literal["success"]
    data: T


class SandboxView(BaseModel):
    id: str
    status: Literal[
        "creating",
        "running",
        "pausing",
        "paused",
        "resuming",
        "forking",
        "error",
        "destroying",
        "destroyed",
        "failed",
    ]
    name: str | None = None
    envs: list[str] = Field(default_factory=list)
    ingress_enabled: bool = False


class Pagination(BaseModel):
    total: int = Field(ge=0)


class SandboxPage(BaseModel):
    data: list[SandboxView]
    pagination: Pagination


class CommandOutput(BaseModel):
    stdout: str
    stderr: str
    exit_code: int
    error: str = ""


class CommandResponse(BaseModel):
    result: CommandOutput


class GuestResult(BaseModel):
    path: str = ""
    stdout_path: str = ""
    stderr_path: str = ""
    exit_code: int = 0
    timed_out_after_s: int | None = None
    error: str | None = None
    errno: int | None = None


class ProviderError(RuntimeError):
    """A control-plane refusal without credential-bearing request or response text."""

    def __init__(self, status: int) -> None:
        self.status = status
        super().__init__(f"CreateOS API returned HTTP {status}")


def sandbox_name(conversation_id: UUID) -> str:
    """Fit the provider's 22-character name limit without shortening the ownership marker."""
    return "ufo-" + hashlib.sha256(conversation_id.bytes).hexdigest()[:NAME_DIGEST_CHARS]


def owner_key(conversation_id: UUID) -> str:
    """Encode ownership in an immutable create-time environment key visible in GET responses."""
    return f"UFO_CONVERSATION_{conversation_id.hex}"


def proxy_rules(addresses: tuple[str, ...], port: int) -> tuple[str, ...]:
    """Produce a nonempty public IPv4 allowlist for the proxy's dedicated address and port."""
    ips = sorted({ipaddress.ip_address(value) for value in addresses}, key=str)
    if not ips or any(ip.version != 4 or not ip.is_global for ip in ips):
        raise ValueError("CreateOS egress proxy must resolve to public IPv4 addresses")
    if not 1 <= port <= 65535:
        raise ValueError("proxy port must be between 1 and 65535")
    return tuple(f"{ip}:{port}" for ip in ips)


@dataclass(frozen=True)
class CreateOSCarrier:
    api_key: str = field(repr=False)
    base_url: str = API_URL
    shape: str = DEFAULT_SHAPE
    _transport: httpx.AsyncBaseTransport | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        parsed = urlsplit(self.base_url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or parsed.path not in ("", "/")
        ):
            raise ValueError("CreateOS base URL must be an HTTPS origin")
        if not self.api_key or any(character in self.api_key for character in "\r\n"):
            raise ValueError("CreateOS API key is missing or invalid")
        if not self.shape:
            raise ValueError("CreateOS shape is required")

    @classmethod
    def from_env(cls) -> "CreateOSCarrier":
        """Resolve host-only credentials and provider settings when the carrier is selected."""
        key = deploy_env(API_KEY_ENV)
        if not key:
            raise RuntimeError(f"set UFO_{API_KEY_ENV} for the createos carrier")
        return cls(
            api_key=key,
            base_url=deploy_env("CREATEOS_SANDBOX_BASE_URL") or API_URL,
            shape=deploy_env("CREATEOS_SANDBOX_SHAPE") or DEFAULT_SHAPE,
        )

    async def create(self, spec: SandboxSpec) -> SandboxHandle:
        """Open the conversation's sandbox and refresh its proxy policy and trust roots."""
        sandbox = await self._find(spec)
        if sandbox is not None:
            self._check_owner(sandbox, spec.conversation_id)
        if sandbox is not None and sandbox.status == "destroying":
            async with asyncio.timeout(LIFECYCLE_TIMEOUT_SECONDS):
                while sandbox is not None and sandbox.status == "destroying":
                    await asyncio.sleep(STATE_POLL_SECONDS)
                    sandbox = await self._get(sandbox.id)
        if spec.resume_id and (sandbox is None or sandbox.status in TERMINAL_STATES):
            sandbox = await self._find(replace(spec, resume_id=None))
        proxy = urlsplit(spec.proxy.public_url or "")
        env = {**GUEST_ENV, **egress_proxy_env(spec.proxy, spec.run_token), **spec.env}
        host = proxy.hostname
        if host is None:
            raise ValueError("CreateOS requires an HTTPS proxy_public_url")
        port = proxy.port or 443
        addresses = await asyncio.get_running_loop().getaddrinfo(
            host, port, family=socket.AF_INET, type=socket.SOCK_STREAM
        )
        ips = tuple(sorted({str(address[4][0]) for address in addresses}))
        rules = proxy_rules(ips, port)
        if sandbox is None:
            if not spec.image_ref.startswith("tpl_"):
                raise ValueError("CreateOS image_ref must be a prepared immutable tpl_ template ID")
            try:
                response = await self._request(
                    "POST",
                    "/v1/sandboxes",
                    {
                        "name": sandbox_name(spec.conversation_id),
                        "shape": self.shape,
                        "rootfs": spec.image_ref,
                        "envs": {owner_key(spec.conversation_id): "1"},
                        "ingress_enabled": False,
                        "egress": rules,
                        "auto_pause_after_seconds": IDLE_TIMEOUT_SECONDS,
                    },
                )
                created = Envelope[SandboxView].model_validate_json(response.content).data
                sandbox = await self._get(created.id)
            except ProviderError as error:
                if error.status != 409:
                    raise
                sandbox = await self._find(replace(spec, resume_id=None))
            if sandbox is None:
                raise SandboxUnreachable("CreateOS did not return the conversation sandbox")
        self._check_owner(sandbox, spec.conversation_id)
        await self._ready(sandbox.id)
        await self._request("PATCH", self._path(sandbox.id), {"ingress_enabled": False})
        await self._request("PUT", self._path(sandbox.id, "/egress"), {"egress": rules})
        await self._guest(
            sandbox.id,
            {
                "action": "prepare",
                "conversation_id": str(spec.conversation_id),
                "ca_cert": spec.proxy.ca_cert,
                "hosts": "\n".join(f"{ip} {host}" for ip in ips),
            },
        )
        return SandboxHandle(
            conversation_id=spec.conversation_id,
            container_id=sandbox.id,
            run_token=spec.run_token,
            egress_env=env,
            turn_id=spec.turn_id,
            runtime_root=sandbox_runtime_root(spec.conversation_id),
        )

    async def attach(self, spec: SandboxSpec) -> SandboxHandle | None:
        """Reattach an existing workspace without provisioning or granting egress credentials."""
        sandbox = await self._find(spec)
        if sandbox is None or sandbox.status in TERMINAL_STATES:
            return None
        self._check_owner(sandbox, spec.conversation_id)
        await self._ready(sandbox.id)
        return SandboxHandle(
            conversation_id=spec.conversation_id,
            container_id=sandbox.id,
            turn_id=spec.turn_id,
            runtime_root=sandbox_runtime_root(spec.conversation_id),
        )

    @staticmethod
    def _check_owner(sandbox: SandboxView, conversation_id: UUID) -> None:
        if owner_key(conversation_id) not in sandbox.envs:
            raise SandboxUnreachable("CreateOS sandbox belongs to another conversation")

    async def _find(self, spec: SandboxSpec) -> SandboxView | None:
        if spec.resume_id:
            return await self._get(spec.resume_id)
        offset = 0
        while True:
            response = await self._request(
                "GET", f"/v1/sandboxes?limit={PAGE_SIZE}&offset={offset}"
            )
            page = Envelope[SandboxPage].model_validate_json(response.content).data
            for sandbox in page.data:
                if (
                    sandbox.name == sandbox_name(spec.conversation_id)
                    and sandbox.status not in TERMINAL_STATES
                ):
                    return sandbox
            offset += len(page.data)
            if not page.data or offset >= page.pagination.total:
                return None

    async def _get(self, sandbox_id: str) -> SandboxView | None:
        response = await self._request("GET", self._path(sandbox_id), missing=True)
        if response.status_code == 404:
            return None
        return Envelope[SandboxView].model_validate_json(response.content).data

    async def _ready(self, sandbox_id: str) -> SandboxView:
        resuming = False
        try:
            async with asyncio.timeout(LIFECYCLE_TIMEOUT_SECONDS):
                while True:
                    sandbox = await self._get(sandbox_id)
                    if sandbox is None or sandbox.status in TERMINAL_STATES:
                        raise SandboxUnreachable(f"CreateOS sandbox {sandbox_id} no longer exists")
                    match sandbox.status:
                        case "running":
                            return sandbox
                        case "paused" | "error" if not resuming:
                            resuming = True
                            try:
                                await self._request("POST", self._path(sandbox_id, "/resume"))
                            except ProviderError as error:
                                if error.status != 409:
                                    raise
                        case "error":
                            raise SandboxProviderUnavailable("CreateOS sandbox failed to resume")
                    await asyncio.sleep(STATE_POLL_SECONDS)
        except TimeoutError as error:
            raise SandboxProviderUnavailable(
                "CreateOS sandbox did not reach running state"
            ) from error

    async def exec(
        self,
        handle: SandboxHandle,
        argv: tuple[str, ...],
        timeout_s: int,
        model_command: str | None = None,
    ) -> ExecResult:
        return await self._exec(handle, argv, timeout_s, privileged=False)

    async def exec_skill(
        self,
        handle: SandboxHandle,
        argv: tuple[str, ...],
        timeout_s: int,
    ) -> ExecResult:
        """Run the runtime's trusted skill installation with root filesystem access."""
        return await self._exec(handle, argv, timeout_s, privileged=True)

    async def _exec(
        self,
        handle: SandboxHandle,
        argv: tuple[str, ...],
        timeout_s: int,
        *,
        privileged: bool,
    ) -> ExecResult:
        if not argv or timeout_s <= 0:
            raise ValueError("command and positive timeout are required")
        stage = await self._guest(handle.container_id, {"action": "stage"})
        completed = False
        try:
            result = await self._guest(
                handle.container_id,
                {
                    "action": "exec",
                    "path": stage.path,
                    "argv": argv,
                    "env": GUEST_ENV if privileged else {**GUEST_ENV, **handle.egress_env},
                    "timeout_s": timeout_s,
                    "turn_id": str(handle.turn_id or ""),
                    "exec_id": uuid4().hex,
                    "privileged": privileged,
                },
                timeout_s=timeout_s + CONTROL_TIMEOUT_SECONDS,
            )
            completed = True
            stdout = b"".join(
                [chunk async for chunk in self._download(handle.container_id, result.stdout_path)]
            )
            stderr = b"".join(
                [chunk async for chunk in self._download(handle.container_id, result.stderr_path)]
            )
            return ExecResult(
                stdout=stdout.decode(errors="replace"),
                stderr=stderr.decode(errors="replace"),
                exit_code=result.exit_code,
                timed_out_after_s=result.timed_out_after_s,
            )
        finally:
            await self._guest(
                handle.container_id,
                {"action": "cleanup" if completed else "abandon", "path": stage.path},
            )

    async def stop_commands(self, handle: SandboxHandle) -> None:
        """Stop only processes launched under this turn, including detached command supervisors."""
        if handle.turn_id is not None:
            await self._guest(
                handle.container_id,
                {
                    "action": "stop",
                    "turn_id": str(handle.turn_id),
                },
            )

    async def write(self, handle: SandboxHandle, path: str, content: bytes) -> None:
        """Stage binary bytes privately and replace the destination as the sandbox user."""
        if len(content) > MAX_FILE_BYTES:
            raise ValueError("CreateOS file upload exceeds 10 GiB")
        stage = await self._guest(handle.container_id, {"action": "stage"})
        try:
            source = f"{stage.path}/input"
            async with self._client() as client:
                response = await client.put(
                    self._path(handle.container_id, "/files"),
                    params={"path": source},
                    content=content,
                    headers={"Content-Type": "application/octet-stream"},
                )
                if not response.is_success:
                    raise ProviderError(response.status_code)
            await self._guest(
                handle.container_id, {"action": "write", "input_path": source, "path": path}
            )
        finally:
            await self._guest(handle.container_id, {"action": "cleanup", "path": stage.path})

    async def read(self, handle: SandboxHandle, path: str) -> AsyncIterator[bytes]:
        """Read with sandbox-user permissions, then stream bounded chunks from private staging."""
        stage = await self._guest(handle.container_id, {"action": "stage"})
        try:
            output = f"{stage.path}/output"
            await self._guest(
                handle.container_id, {"action": "read", "path": path, "output_path": output}
            )
            async for chunk in self._download(handle.container_id, output):
                yield chunk
        finally:
            await self._guest(handle.container_id, {"action": "cleanup", "path": stage.path})

    async def _download(self, sandbox_id: str, path: str) -> AsyncIterator[bytes]:
        async with self._client() as client:
            async with client.stream(
                "GET", self._path(sandbox_id, "/files"), params={"path": path}
            ) as response:
                if not response.is_success:
                    raise ProviderError(response.status_code)
                async for chunk in response.aiter_bytes(READ_CHUNK_BYTES):
                    yield chunk

    async def file_op(
        self, handle: SandboxHandle, op: str, params: dict[str, object]
    ) -> dict[str, object]:
        return await ufo_fs_file_op(self, handle, op, params)

    @cached_property
    def _tunnels(self) -> CreateOSTunnels:
        return CreateOSTunnels(api_key=self.api_key, base_url=self.base_url)

    async def dial(self, handle: SandboxHandle, port: int) -> DialTarget:
        """Reach a sandbox service through an authenticated private TCP tunnel."""
        try:
            sandbox = await self._ready(handle.container_id)
            self._check_owner(sandbox, handle.conversation_id)
            return await self._tunnels.dial(handle.container_id, port)
        except (httpx.HTTPError, ProviderError, OSError, SandboxProviderUnavailable) as error:
            raise SandboxUnreachable("CreateOS private tunnel is unavailable") from error

    async def aclose(self) -> None:
        """Close this process's local forwarding listeners and active tunnels."""
        await self._tunnels.aclose()

    async def _guest(
        self,
        sandbox_id: str,
        payload: Mapping[str, object],
        *,
        timeout_s: int = CONTROL_TIMEOUT_SECONDS,
    ) -> GuestResult:
        response = await self._request(
            "POST",
            self._path(sandbox_id, "/exec"),
            {
                "cmd": "python3",
                "args": ["-I", "-c", GUEST_SOURCE],
                "stdin": json.dumps(payload, separators=(",", ":")),
            },
            timeout_s=timeout_s,
        )
        command = Envelope[CommandResponse].model_validate_json(response.content).data.result
        if command.error or command.exit_code:
            raise RuntimeError(f"CreateOS guest helper failed with exit code {command.exit_code}")
        result = GuestResult.model_validate_json(command.stdout)
        if result.error is not None:
            if result.errno is not None:
                raise OSError(result.errno, result.error)
            raise RuntimeError(result.error)
        match payload["action"]:
            case "stage":
                path = Path(result.path)
                if path.parent != Path("/var/lib/ufo-carrier") or UUID(path.name).hex != path.name:
                    raise RuntimeError("CreateOS guest returned an invalid staging path")
            case "exec":
                required = {"stdout_path", "stderr_path", "exit_code", "timed_out_after_s"}
                if (
                    not required <= result.model_fields_set
                    or result.stdout_path != f"{payload['path']}/stdout"
                    or result.stderr_path != f"{payload['path']}/stderr"
                ):
                    raise RuntimeError("CreateOS guest returned an incomplete command result")
        return result

    @staticmethod
    def _path(sandbox_id: str, suffix: str = "") -> str:
        return f"/v1/sandboxes/{quote(sandbox_id, safe='')}{suffix}"

    def _client(self, timeout_s: int = CONTROL_TIMEOUT_SECONDS) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=self.base_url,
            headers={"X-Api-Key": self.api_key},
            timeout=timeout_s,
            follow_redirects=False,
            transport=self._transport,
            trust_env=False,
        )

    async def _request(
        self,
        method: str,
        path: str,
        body: Mapping[str, object] | None = None,
        *,
        missing: bool = False,
        timeout_s: int = CONTROL_TIMEOUT_SECONDS,
    ) -> httpx.Response:
        content = None if body is None else json.dumps(body, separators=(",", ":")).encode()
        if content is not None and len(content) > MAX_REQUEST_BYTES:
            raise ValueError("CreateOS request exceeds 256 KiB; use file transfer")
        async with self._client(timeout_s) as client:
            response = await client.request(
                method,
                path,
                content=content,
                headers={"Content-Type": "application/json"},
            )
        if not response.is_success and not (missing and response.status_code == 404):
            raise ProviderError(response.status_code)
        return response


def manifest() -> Manifest:
    return Manifest(
        name=NAME,
        version="0.1.0",
        deploy_keys=(API_KEY_ENV,),
        carriers=(CarrierSpec(name=NAME, factory=CreateOSCarrier.from_env, off_cluster=True),),
    )
