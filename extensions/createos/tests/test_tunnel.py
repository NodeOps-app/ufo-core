import asyncio
import contextlib
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import pytest
import ufo_ext_createos.tunnel as tunnel_module
from ufo_ext_createos.tunnel import MAX_HEADER_BYTES, CreateOSTunnels

UPGRADE = b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: tcp-tunnel\r\n\r\n"


@asynccontextmanager
async def tunnel_peer(
    response: bytes = UPGRADE,
) -> AsyncIterator[tuple[CreateOSTunnels, asyncio.Queue[bytes], asyncio.Event]]:
    requests: asyncio.Queue[bytes] = asyncio.Queue()
    closed = asyncio.Event()
    connections: set[asyncio.Task[None]] = set()

    async def respond(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            requests.put_nowait(await reader.readuntil(b"\r\n\r\n"))
            writer.write(response)
            await writer.drain()
            while data := await reader.read(65536):
                writer.write(data)
                await writer.drain()
        except (OSError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()
            closed.set()

    def accept(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.create_task(respond(reader, writer))
        connections.add(task)
        task.add_done_callback(connections.discard)

    server = await asyncio.start_server(accept, "127.0.0.1", 0)
    tunnels = CreateOSTunnels("secret", f"http://127.0.0.1:{server.sockets[0].getsockname()[1]}")
    try:
        async with asyncio.timeout(5):
            yield tunnels, requests, closed
    finally:
        await tunnels.aclose()
        server.close()
        pending = tuple(connections)
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
        await server.wait_closed()


async def test_tunnel_preserves_coalesced_bytes_and_binary_payloads() -> None:
    greeting = b"\x00\xffhello"
    async with tunnel_peer(UPGRADE + greeting) as (tunnels, requests, _):
        target = await tunnels.dial("sb-example", 8080)
        assert target == await tunnels.dial("sb-example", 8080)
        assert target.tls is False
        assert not target.headers
        host, port = target.host.split(":")
        reader, writer = await asyncio.open_connection(host, int(port))
        try:
            assert await reader.readexactly(len(greeting)) == greeting
            request = await requests.get()
            assert request.startswith(b"POST /v1/sandboxes/sb-example/tunnel/8080 HTTP/1.1\r\n")
            assert b"X-Api-Key: secret\r\n" in request
            payload = bytes(range(256)) * 1024
            writer.write(payload)
            await writer.drain()
            assert await reader.readexactly(len(payload)) == payload
        finally:
            writer.close()
            await writer.wait_closed()


@pytest.mark.parametrize(
    "response",
    [
        b"HTTP/1.1 403 Forbidden\r\nContent-Length: 6\r\n\r\nsecret",
        b"HTTP/1.1 302 Found\r\nLocation: http://example.com/\r\n\r\n",
        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: tcp-tunnel\r\n\r\n",
        b"HTTP/1.1 101 Switching Protocols\r\nX-Large: " + b"a" * MAX_HEADER_BYTES + b"\r\n\r\n",
    ],
)
async def test_rejected_upgrade_closes_connection_without_forwarding(response: bytes) -> None:
    async with tunnel_peer(response) as (tunnels, _, closed):
        target = await tunnels.dial("sb-example", 8080)
        host, port = target.host.split(":")
        reader, writer = await asyncio.open_connection(host, int(port))
        try:
            assert await reader.read() == b""
            await closed.wait()
        finally:
            writer.close()
            await writer.wait_closed()


async def test_shutdown_closes_active_connections_and_listener() -> None:
    async with tunnel_peer(UPGRADE + b"ready") as (tunnels, _, closed):
        target = await tunnels.dial("sb-example", 8080)
        host, port = target.host.split(":")
        reader, writer = await asyncio.open_connection(host, int(port))
        try:
            assert await reader.readexactly(5) == b"ready"
            await tunnels.aclose()
            assert await reader.read() == b""
            await closed.wait()
            with pytest.raises(OSError):
                await asyncio.open_connection(host, int(port))
            with pytest.raises(RuntimeError, match="closed"):
                await tunnels.dial("sb-example", 8080)
        finally:
            writer.close()
            await writer.wait_closed()


async def test_client_half_close_releases_upstream() -> None:
    async with tunnel_peer(UPGRADE + b"ready") as (tunnels, _, closed):
        target = await tunnels.dial("sb-example", 8080)
        host, port = target.host.split(":")
        reader, writer = await asyncio.open_connection(host, int(port))
        try:
            assert await reader.readexactly(5) == b"ready"
            writer.write_eof()
            assert await reader.read() == b""
            await closed.wait()
        finally:
            writer.close()
            await writer.wait_closed()


async def test_each_client_gets_an_independent_authenticated_tunnel() -> None:
    async with tunnel_peer(UPGRADE + b"ready") as (tunnels, requests, _):
        target = await tunnels.dial("sb-example", 8080)
        host, port = target.host.split(":")
        first_reader, first_writer = await asyncio.open_connection(host, int(port))
        second_reader, second_writer = await asyncio.open_connection(host, int(port))
        try:
            assert await first_reader.readexactly(5) == b"ready"
            assert await second_reader.readexactly(5) == b"ready"
            assert await requests.get() == await requests.get()
            first_writer.close()
            await first_writer.wait_closed()
            second_writer.write(b"independent")
            await second_writer.drain()
            assert await second_reader.readexactly(11) == b"independent"
        finally:
            first_writer.close()
            second_writer.close()
            await asyncio.gather(first_writer.wait_closed(), second_writer.wait_closed())


async def test_incomplete_upgrade_reaches_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tunnel_module, "HANDSHAKE_TIMEOUT_SECONDS", 0.05)
    async with tunnel_peer(b"HTTP/1.1 101") as (tunnels, _, closed):
        target = await tunnels.dial("sb-example", 8080)
        host, port = target.host.split(":")
        reader, writer = await asyncio.open_connection(host, int(port))
        try:
            assert await reader.read() == b""
            await closed.wait()
        finally:
            writer.close()
            await writer.wait_closed()


@pytest.mark.parametrize(
    "url",
    ["http://example.com/v1", "https://user:pass@example.com/v1", "https://example.com/v1?token=x"],
)
def test_tunnel_rejects_unsafe_api_url(url: str) -> None:
    with pytest.raises(ValueError, match="HTTPS or loopback"):
        CreateOSTunnels("secret", url)


def test_tunnel_rejects_header_injection() -> None:
    with pytest.raises(ValueError, match="API key"):
        CreateOSTunnels("secret\r\nInjected: header", "https://api.example.com/v1")
