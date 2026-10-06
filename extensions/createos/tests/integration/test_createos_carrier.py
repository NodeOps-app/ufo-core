import asyncio
import base64
import hashlib
import os
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from ufo_ext_createos.carrier import CreateOSCarrier

from ufo.sdk.sandbox import ProxyEndpoint, SandboxSession, SandboxSpec

TEMPLATE = os.environ.get("UFO_CREATEOS_TEST_TEMPLATE")
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not TEMPLATE, reason="set UFO_CREATEOS_TEST_TEMPLATE to opt in"),
]


async def test_live_createos_carrier() -> None:
    carrier = CreateOSCarrier.from_env()
    second = CreateOSCarrier.from_env()
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ufo test CA")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(minutes=1))
        .not_valid_after(datetime.now(UTC) + timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
        .public_bytes(serialization.Encoding.PEM)
        .decode()
    )
    spec = SandboxSpec(
        conversation_id=uuid4(),
        image_ref=TEMPLATE or "",
        workspace_host_path="/unused",
        proxy=ProxyEndpoint(port=443, ca_cert=cert, public_url="https://example.com"),
        run_token="first-turn",
        turn_id=uuid4(),
        env={"TEST_VALUE": "first"},
    )
    try:
        assert await carrier.attach(spec) is None
        handle = await carrier.create(spec)
        sandbox = SandboxSession(carrier=carrier, handle=handle)
        result = await sandbox.sh('printf "%s:%s:%s" "$(id -u)" "$TEST_VALUE" "$HTTPS_PROXY"')
        assert result.stdout.startswith("1000:first:https://first-turn:")
        assert carrier.api_key not in result.stdout
        result = await sandbox.python("print('x' * 2097408, end='')")
        assert len(result.stdout) == 2097408
        content = bytes(range(256)) * 8193
        path = "/workspace/nested/quotes ' and spaces.bin"
        await sandbox.write_file(path, content)
        chunks = [chunk async for chunk in sandbox.read_file(path)]
        assert b"".join(chunks) == content
        assert max(map(len, chunks)) <= 1024 * 1024
        with pytest.raises(FileNotFoundError):
            _ = [chunk async for chunk in sandbox.read_file("/workspace/missing")]
        with pytest.raises(PermissionError):
            _ = [chunk async for chunk in carrier.read(handle, "/etc/shadow")]
        with pytest.raises(PermissionError):
            await carrier.write(handle, "/etc/ufo-member-write", b"denied")
        await sandbox.write_file("/workspace/hello.txt", b"hello createos\n")
        assert "hello createos" in str(
            await sandbox.run_ufo_fs("read", {"path": "/workspace/hello.txt"})
        )
        skill_content = b"CreateOS skill transfer fixture\n"
        digest = hashlib.sha256(
            hashlib.sha256(b"reference.txt").digest() + hashlib.sha256(skill_content).digest()
        ).hexdigest()
        roots = await sandbox.load_skills(
            {
                "system": {},
                "user": {
                    "transfer-probe": {
                        "digest": f"sha256:{digest}",
                        "files": {
                            "reference.txt": base64.urlsafe_b64encode(skill_content).decode()
                        },
                    }
                },
            }
        )
        loaded = roots["transfer-probe"] + "/reference.txt"
        assert b"".join([chunk async for chunk in carrier.read(handle, loaded)]) == skill_content
        assert (await sandbox.sh("test -w /home/user/.ufo/skills")).exit_code != 0
        deadline = await sandbox.sh("sleep 30", timeout_s=1)
        assert deadline.exit_code == 124 and deadline.timed_out_after_s == 1
        chosen = await sandbox.sh("exit 124")
        assert chosen.exit_code == 124 and chosen.timed_out_after_s is None
        assert (await carrier.exec(handle, ("no-such-ufo-command",), 10)).exit_code == 127
        blocked = await sandbox.python(
            "import socket; socket.create_connection(('1.1.1.1', 443), timeout=2)"
        )
        assert blocked.exit_code != 0
        serving = await sandbox.python(
            "import os,subprocess,socket; "
            "listener=socket.create_server(('127.0.0.1',8765)); "
            "subprocess.Popen(['python3','-c', "
            '"import http.server,socket; '
            "server=http.server.HTTPServer(('127.0.0.1',8765), "
            "http.server.SimpleHTTPRequestHandler,bind_and_activate=False); "
            "server.socket=socket.socket(fileno=int(__import__('sys').argv[1])); "
            'server.serve_forever()",str(listener.fileno())], '
            "pass_fds=(listener.fileno(),), "
            "stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)"
        )
        assert serving.exit_code == 0
        target = await carrier.dial(handle, 8765)
        async with httpx.AsyncClient(trust_env=False) as client:
            response = await client.get(f"http://{target.host}/hello.txt")
            assert response.text == "hello createos\n"
        await carrier.aclose()
        await carrier._request("POST", carrier._path(handle.container_id, "/pause"))
        attached = await second.attach(replace(spec, resume_id=handle.container_id, turn_id=None))
        assert attached is not None and not attached.egress_env
        assert b"".join([chunk async for chunk in second.read(attached, path)]) == content
        attached_session = SandboxSession(carrier=second, handle=attached)
        assert "hello createos" in str(
            await attached_session.run_ufo_fs("read", {"path": "/workspace/hello.txt"})
        )
        resumed = await second.create(
            replace(
                spec,
                resume_id=handle.container_id,
                run_token="second-turn",
                env={"TEST_VALUE": "second"},
            )
        )
        assert resumed.container_id == handle.container_id
        result = await second.exec(resumed, ("sh", "-c", 'echo "$TEST_VALUE:$HTTPS_PROXY"'), 10)
        assert result.stdout.startswith("second:https://second-turn:")
        assert (
            await second.attach(
                replace(spec, conversation_id=uuid4(), resume_id=handle.container_id)
            )
            is None
        )
        sibling = replace(resumed, turn_id=uuid4())
        waiting = (
            "import pathlib,sys,time; pathlib.Path(sys.argv[1]).touch(); "
            "\nwhile not pathlib.Path('/workspace/release').exists(): time.sleep(.05)"
        )
        first = asyncio.create_task(
            second.exec(resumed, ("python3", "-c", waiting, "/workspace/first"), 60)
        )
        other = asyncio.create_task(
            second.exec(sibling, ("python3", "-c", waiting, "/workspace/other"), 60)
        )
        try:
            ready = await second.exec(
                resumed,
                (
                    "python3",
                    "-c",
                    "import pathlib,time\n"
                    "while not all(pathlib.Path('/workspace/' + name).exists() "
                    "for name in ('first', 'other')): time.sleep(.05)",
                ),
                10,
            )
            assert ready.exit_code == 0
            await second.stop_commands(resumed)
            assert (await asyncio.wait_for(first, 15)).exit_code != 0
            assert not other.done()
            with pytest.raises(OSError, match="turn has been stopped"):
                await second.exec(resumed, ("touch", "/workspace/late-command"), 10)
            with pytest.raises(FileNotFoundError):
                _ = [
                    chunk
                    async for chunk in second.read(
                        replace(resumed, turn_id=None), "/workspace/late-command"
                    )
                ]
            await second.write(sibling, "/workspace/release", b"")
            assert (await asyncio.wait_for(other, 15)).exit_code == 0
        finally:
            await second.stop_commands(sibling)
            await asyncio.gather(first, other, return_exceptions=True)
        paused_turn = replace(resumed, turn_id=uuid4())
        await second._request("POST", second._path(handle.container_id, "/pause"))
        await second.stop_commands(paused_turn)
        with pytest.raises(OSError, match="turn has been stopped"):
            await second.exec(paused_turn, ("touch", "/workspace/paused-late-command"), 10)
        with pytest.raises(FileNotFoundError):
            _ = [
                chunk
                async for chunk in second.read(
                    replace(resumed, turn_id=None), "/workspace/paused-late-command"
                )
            ]
        await second._request("DELETE", second._path(handle.container_id))
        assert await second.attach(replace(spec, resume_id=handle.container_id)) is None
        replacement = await second.create(replace(spec, resume_id=handle.container_id))
        assert replacement.container_id != handle.container_id
        recovered = await second.create(replace(spec, resume_id=handle.container_id))
        assert recovered.container_id == replacement.container_id
        with pytest.raises(FileNotFoundError):
            _ = [chunk async for chunk in second.read(replacement, path)]
    finally:
        await carrier.aclose()
        await second.aclose()
        held = await carrier._find(spec)
        if held is not None:
            await carrier._request("DELETE", carrier._path(held.id))
