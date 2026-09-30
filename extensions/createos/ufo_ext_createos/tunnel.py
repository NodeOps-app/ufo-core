import asyncio
import contextlib
import ssl
from dataclasses import dataclass, field
from functools import partial
from urllib.parse import quote, urlsplit

from ufo.sdk.sandbox import DialTarget

HANDSHAKE_TIMEOUT_SECONDS = 15
MAX_HEADER_BYTES = 16384
COPY_BYTES = 65536


@dataclass(frozen=True)
class CreateOSTunnels:
    """Expose authenticated CreateOS TCP upgrades through process-local listeners."""

    api_key: str = field(repr=False)
    base_url: str = "https://api.sb.createos.sh"
    _servers: dict[tuple[str, int], asyncio.Server] = field(default_factory=dict, init=False)
    _connections: set[asyncio.Task[None]] = field(default_factory=set, init=False)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock, init=False)
    _closed: asyncio.Event = field(default_factory=asyncio.Event, init=False)
    _tls: ssl.SSLContext = field(default_factory=ssl.create_default_context, init=False, repr=False)

    def __post_init__(self) -> None:
        url = urlsplit(self.base_url)
        if (
            not url.hostname
            or url.username is not None
            or url.password is not None
            or url.query
            or url.fragment
            or url.scheme not in {"https", "http"}
            or (url.scheme == "http" and url.hostname not in {"127.0.0.1", "::1", "localhost"})
        ):
            raise ValueError("CreateOS tunnel URL requires HTTPS or loopback HTTP")
        if not self.api_key or any(ord(char) < 33 or ord(char) > 126 for char in self.api_key):
            raise ValueError("Invalid CreateOS API key")

    async def dial(self, sandbox_id: str, port: int) -> DialTarget:
        """Return a local endpoint that upgrades each accepted connection independently."""
        if not sandbox_id or not 1 <= port <= 65535:
            raise ValueError("Invalid sandbox tunnel destination")
        async with self._lock:
            if self._closed.is_set():
                raise RuntimeError("CreateOS tunnels are closed")
            key = sandbox_id, port
            if key not in self._servers:
                self._servers[key] = await asyncio.start_server(
                    partial(self._accept, sandbox_id, port), "127.0.0.1", 0
                )
            address = self._servers[key].sockets[0].getsockname()
            return DialTarget(host=f"127.0.0.1:{address[1]}", tls=False)

    def _accept(
        self, sandbox_id: str, port: int, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        if self._closed.is_set():
            writer.close()
            return
        task = asyncio.create_task(self._forward(sandbox_id, port, reader, writer))
        self._connections.add(task)
        task.add_done_callback(self._connections.discard)

    async def _forward(
        self,
        sandbox_id: str,
        port: int,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        upstream: asyncio.StreamWriter | None = None
        copies: list[asyncio.Task[None]] = []
        try:
            remote, upstream = await self._upgrade(sandbox_id, port)
            copies = [
                asyncio.create_task(self._copy(reader, upstream)),
                asyncio.create_task(self._copy(remote, writer)),
            ]
            await asyncio.wait(copies, return_when=asyncio.FIRST_COMPLETED)
        except (
            OSError,
            ValueError,
            TimeoutError,
            asyncio.IncompleteReadError,
            asyncio.LimitOverrunError,
        ):
            pass
        finally:
            for task in copies:
                task.cancel()
            await asyncio.gather(*copies, return_exceptions=True)
            for stream in (writer, upstream):
                if stream is not None:
                    stream.close()
                    with contextlib.suppress(OSError):
                        await stream.wait_closed()

    async def _upgrade(
        self, sandbox_id: str, port: int
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        url = urlsplit(self.base_url)
        writer: asyncio.StreamWriter | None = None
        try:
            async with asyncio.timeout(HANDSHAKE_TIMEOUT_SECONDS):
                reader, writer = await asyncio.open_connection(
                    url.hostname,
                    url.port or (443 if url.scheme == "https" else 80),
                    ssl=self._tls if url.scheme == "https" else None,
                    limit=MAX_HEADER_BYTES,
                )
                path = (
                    f"{url.path.rstrip('/')}/v1/sandboxes/"
                    f"{quote(sandbox_id, safe='')}/tunnel/{port}"
                )
                writer.write(
                    (
                        f"POST {path} HTTP/1.1\r\nHost: {url.netloc}\r\n"
                        f"X-Api-Key: {self.api_key}\r\n"
                        "Connection: Upgrade\r\nUpgrade: tcp-tunnel\r\nContent-Length: 0\r\n\r\n"
                    ).encode("ascii")
                )
                await writer.drain()
                response = await reader.readuntil(b"\r\n\r\n")
                if len(response) > MAX_HEADER_BYTES:
                    raise ValueError("CreateOS tunnel response headers exceed limit")
                lines = response.decode("ascii").split("\r\n")
                status = lines[0].split(" ", 2)
                headers: dict[str, str] = {}
                for line in lines[1:-2]:
                    name, separator, value = line.partition(":")
                    if not separator or name.lower() in headers:
                        raise ValueError("Invalid CreateOS tunnel response headers")
                    headers[name.lower()] = value.strip().lower()
                if (
                    status[:2] != ["HTTP/1.1", "101"]
                    or headers.get("upgrade") != "tcp-tunnel"
                    or "upgrade" not in headers.get("connection", "").replace(" ", "").split(",")
                ):
                    raise ValueError("CreateOS tunnel upgrade rejected")
                return reader, writer
        except BaseException:
            if writer is not None:
                writer.close()
                with contextlib.suppress(OSError):
                    await writer.wait_closed()
            raise

    async def _copy(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        while data := await reader.read(COPY_BYTES):
            writer.write(data)
            await writer.drain()

    async def aclose(self) -> None:
        """Close forwarding listeners and cancel their active connections."""
        async with self._lock:
            self._closed.set()
            for server in self._servers.values():
                server.close()
            tasks = tuple(self._connections)
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            await asyncio.gather(*(server.wait_closed() for server in self._servers.values()))
            self._servers.clear()
