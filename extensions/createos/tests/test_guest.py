import json
import subprocess
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

import pytest

SOURCE = Path(__file__).parents[1].joinpath("ufo_ext_createos/guest.py").read_text()
IMAGE = "python:3.12-slim"
pytestmark = pytest.mark.docker


@dataclass(frozen=True)
class LinuxGuest:
    container: str

    def request(self, action: str, **fields: object) -> dict[str, object]:
        result = subprocess.run(
            ["docker", "exec", "-i", self.container, "python3", "-I", "-c", SOURCE],
            input=json.dumps({"action": action, **fields}),
            text=True,
            capture_output=True,
            check=True,
        )
        return json.loads(result.stdout)

    def command(self, source: str) -> str:
        return subprocess.run(
            ["docker", "exec", self.container, "python3", "-c", source],
            text=True,
            capture_output=True,
            check=True,
        ).stdout


@pytest.fixture(scope="module")
def linux_guest() -> Iterator[LinuxGuest]:
    container = subprocess.run(
        [
            "docker",
            "run",
            "-d",
            "--rm",
            "--privileged",
            "--cgroupns=private",
            IMAGE,
            "sleep",
            "infinity",
        ],
        text=True,
        capture_output=True,
        check=True,
    ).stdout.strip()
    guest = LinuxGuest(container)
    try:
        subprocess.run(
            ["docker", "exec", container, "mount", "-o", "remount,rw", "/sys/fs/cgroup"],
            check=True,
            capture_output=True,
        )
        guest.command(
            "import os, pathlib; "
            "pathlib.Path('/workspace').mkdir(); os.chown('/workspace',1000,1000); "
            "pathlib.Path('/etc/passwd').open('a').write("
            "'user:x:1000:1000::/home/user:/bin/sh\\n'); "
            "pathlib.Path('/home/user').mkdir(); "
            "pathlib.Path('/usr/local/bin/ufo').write_text('#!/bin/sh\\n'); "
            "os.chmod('/usr/local/bin/ufo',0o755)"
        )
        yield guest
    finally:
        subprocess.run(["docker", "rm", "-f", container], check=True, capture_output=True)


def test_prepare_and_stage_reject_user_controlled_directories(linux_guest: LinuxGuest) -> None:
    conversation = uuid4()
    result = linux_guest.request(
        "prepare", conversation_id=str(conversation), hosts="10.0.0.1 proxy.test"
    )
    assert result == {"runtime_root": f"/home/user/.ufo/runs/{conversation.hex}"}
    assert (
        linux_guest.request(
            "prepare", conversation_id=str(conversation), hosts="10.0.0.2 proxy.test"
        )
        == result
    )
    hosts = linux_guest.command("from pathlib import Path; print(Path('/etc/hosts').read_text())")
    assert "10.0.0.1 proxy.test" not in hosts
    assert hosts.count("10.0.0.2 proxy.test") == 1
    stage = linux_guest.request("stage")["path"]
    assert (
        linux_guest.command(f"import os; print(oct(os.stat({stage!r}).st_mode & 0o777))").strip()
        == "0o700"
    )
    assert linux_guest.request("cleanup", path=stage) == {}

    linux_guest.command("import os; os.chmod('/home/user',0o777)")
    try:
        assert linux_guest.request("prepare", conversation_id=str(uuid4()))["errno"] == 1
    finally:
        linux_guest.command("import os; os.chmod('/home/user',0o755)")
    assert linux_guest.request("cleanup", path="/workspace")["errno"] == 1


@pytest.mark.parametrize("argv,code", [(["/missing"], 127), (["/etc/shadow"], 126)])
def test_exec_reports_launch_failure(linux_guest: LinuxGuest, argv: list[str], code: int) -> None:
    stage = linux_guest.request("stage")["path"]
    result = linux_guest.request("exec", path=stage, exec_id=uuid4().hex, argv=argv)
    assert result["exit_code"] == code
    assert result["timed_out_after_s"] is None
    linux_guest.request("cleanup", path=stage)


def test_prepare_restores_writable_paths_from_root_owned_template(linux_guest: LinuxGuest) -> None:
    linux_guest.command(
        "import os,pathlib; "
        "pathlib.Path('/home/user/.ufo').mkdir(exist_ok=True); "
        "pathlib.Path('/home/user/.ufo/session').write_text('retained'); "
        "os.chown('/home/user/.ufo/session',0,0); "
        "os.chmod('/home/user/.ufo/session',0o600); os.chown('/workspace',0,0)"
    )
    assert "error" not in linux_guest.request("prepare", conversation_id=str(uuid4()))
    stage = linux_guest.request("stage")["path"]
    result = linux_guest.request(
        "exec",
        path=stage,
        exec_id=uuid4().hex,
        argv=[
            "python3",
            "-c",
            "from pathlib import Path; "
            "Path('/workspace/ownership-probe').write_text('ok'); "
            "p=Path('/home/user/.ufo/session'); assert p.read_text()=='retained'; "
            "p.write_text('updated')",
        ],
        env={"PATH": "/usr/local/bin:/usr/bin:/bin"},
    )
    assert result["exit_code"] == 0
    assert linux_guest.request("cleanup", path=stage) == {}


def test_exec_isolates_identity_environment_and_large_output(linux_guest: LinuxGuest) -> None:
    stage = linux_guest.request("stage")["path"]
    result = linux_guest.request(
        "exec",
        path=stage,
        turn_id="turn",
        exec_id=uuid4().hex,
        argv=[
            "python3",
            "-c",
            "import os,sys; print(os.getuid(),os.getgid(),os.getgroups(),"
            'os.getcwd(),os.getenv("HOME")); sys.stderr.write("x"*2000000)',
        ],
        env={"PATH": "/usr/local/bin:/usr/bin:/bin"},
    )
    assert result["exit_code"] == 0
    assert result["timed_out_after_s"] is None
    assert (
        linux_guest.command(
            f'from pathlib import Path; print(Path({result["stdout_path"]!r}).read_text(),end="")'
        )
        == "1000 1000 [] /workspace None\n"
    )
    assert (
        linux_guest.command(f"import os; print(os.stat({result['stderr_path']!r}).st_size)").strip()
        == "2000000"
    )
    assert linux_guest.request("cleanup", path=stage) == {}


def test_file_transfer_preserves_bytes_modes_and_user_permissions(linux_guest: LinuxGuest) -> None:
    stage = linux_guest.request("stage")["path"]
    incoming = f"{stage}/incoming"
    outgoing = f"{stage}/outgoing"
    target = f"/workspace/{uuid4().hex}/data"
    linux_guest.command(
        f"from pathlib import Path; Path({incoming!r}).write_bytes(bytes(range(256))*10000)"
    )
    assert linux_guest.request("write", input_path=incoming, path=target) == {}
    linux_guest.command(f"import os; os.chmod({target!r},0o750)")
    assert linux_guest.request("write", input_path=incoming, path=target) == {}
    assert (
        linux_guest.command(f"import os; print(oct(os.stat({target!r}).st_mode & 0o777))").strip()
        == "0o750"
    )
    assert linux_guest.request("read", path=target, output_path=outgoing) == {}
    assert (
        linux_guest.command(
            f"from pathlib import Path; "
            f"print(Path({incoming!r}).read_bytes() == Path({outgoing!r}).read_bytes())"
        ).strip()
        == "True"
    )
    assert linux_guest.request("write", input_path=incoming, path="/etc/blocked")["errno"] == 13
    assert (
        linux_guest.request("read", path="/etc/shadow", output_path=f"{stage}/secret")["errno"]
        == 13
    )
    assert (
        linux_guest.request("read", path="/missing", output_path=f"{stage}/missing")["errno"] == 2
    )
    assert linux_guest.request("cleanup", path=stage) == {}


def test_timeout_kills_detached_descendant_and_stop_preserves_sibling(
    linux_guest: LinuxGuest,
) -> None:
    stage = linux_guest.request("stage")["path"]
    target = f"/workspace/{uuid4().hex}"
    source = (
        "import subprocess,time; "
        'p=subprocess.Popen(["/bin/sleep","300"],env={},start_new_session=True); '
        f'open({target!r},"w").write(str(p.pid)); time.sleep(300)'
    )
    result = linux_guest.request(
        "exec",
        path=stage,
        turn_id="timeout-turn",
        exec_id=uuid4().hex,
        argv=["python3", "-c", source],
        env={"PATH": "/usr/local/bin:/usr/bin:/bin"},
        timeout_s=1,
    )
    assert result["exit_code"] == 124
    assert result["timed_out_after_s"] == 1
    assert (
        linux_guest.command(
            f'from pathlib import Path; p=Path("/proc")/Path({target!r}).read_text()/"stat"; '
            'print(not p.exists() or p.read_text().split()[2] == "Z")'
        ).strip()
        == "True"
    )
    pids = []
    for turn in ("stopped-turn", "sibling-turn"):
        turn_stage = linux_guest.request("stage")["path"]
        result = linux_guest.request(
            "exec",
            path=turn_stage,
            turn_id=turn,
            exec_id=uuid4().hex,
            argv=[
                "python3",
                "-c",
                "import subprocess; "
                'print(subprocess.Popen(["/bin/sleep","300"],env={},start_new_session=True).pid)',
            ],
            env={"PATH": "/usr/local/bin:/usr/bin:/bin"},
        )
        pids.append(
            int(
                linux_guest.command(
                    f"from pathlib import Path; print(Path({result['stdout_path']!r}).read_text())"
                )
            )
        )
        linux_guest.request("cleanup", path=turn_stage)
    assert linux_guest.request("stop", turn_id="stopped-turn") == {}
    assert (
        linux_guest.command(
            f'from pathlib import Path; p=Path("/proc/{pids[0]}/stat"); '
            'print(not p.exists() or p.read_text().split()[2] == "Z")'
        ).strip()
        == "True"
    )
    assert (
        linux_guest.command(
            f"from pathlib import Path; "
            f'print(Path("/proc/{pids[1]}/stat").read_text().split()[2] != "Z")'
        ).strip()
        == "True"
    )
    linux_guest.request("stop", turn_id="sibling-turn")
    linux_guest.request("cleanup", path=stage)


def test_prepare_serializes_concurrent_same_conversation(linux_guest: LinuxGuest) -> None:
    conversation = str(uuid4())
    with ThreadPoolExecutor(max_workers=4) as workers:
        results = list(
            workers.map(
                lambda _: linux_guest.request(
                    "prepare", conversation_id=conversation, hosts="10.0.0.3 parallel.proxy"
                ),
                range(4),
            )
        )
    assert all(result == results[0] for result in results)
    assert "runtime_root" in results[0]
    hosts = linux_guest.command("from pathlib import Path; print(Path('/etc/hosts').read_text())")
    assert hosts.count("10.0.0.3 parallel.proxy") == 1


@pytest.mark.parametrize("abandon_first", [True, False])
def test_abandon_reclaims_execution_stage(linux_guest: LinuxGuest, abandon_first: bool) -> None:
    stage = linux_guest.request("stage")["path"]
    if abandon_first:
        assert linux_guest.request("abandon", path=stage) == {}
    result = linux_guest.request("exec", path=stage, exec_id=uuid4().hex, argv=["/bin/true"])
    assert result["exit_code"] == 0
    if not abandon_first:
        assert linux_guest.request("abandon", path=stage) == {}
    assert (
        linux_guest.command(f"from pathlib import Path; print(Path({stage!r}).exists())").strip()
        == "False"
    )
    assert linux_guest.request("cleanup", path=stage) == {}
    assert linux_guest.request("abandon", path=stage) == {}


def test_abandon_retains_stage_until_running_execution_finishes(linux_guest: LinuxGuest) -> None:
    stage = linux_guest.request("stage")["path"]
    ready = f"/workspace/{uuid4().hex}"
    release = f"/workspace/{uuid4().hex}"
    linux_guest.command(
        f"import os; os.mkfifo({ready!r},0o666); os.mkfifo({release!r},0o666); "
        f"os.chmod({ready!r},0o666); os.chmod({release!r},0o666)"
    )
    with ThreadPoolExecutor(max_workers=1) as workers:
        execution = workers.submit(
            linux_guest.request,
            "exec",
            path=stage,
            exec_id=uuid4().hex,
            argv=[
                "/usr/local/bin/python3",
                "-c",
                f"with open({ready!r},'w') as ready: ready.write('ready')\n"
                f"with open({release!r}) as release: release.read()\n"
                "print('finished')",
            ],
        )
        assert linux_guest.command(f"print(open({ready!r}).read())").strip() == "ready"
        assert linux_guest.request("abandon", path=stage) == {}
        assert (
            linux_guest.command(
                f"from pathlib import Path; print(Path({stage!r}).exists())"
            ).strip()
            == "True"
        )
        linux_guest.command(f"open({release!r},'w').close()")
        assert execution.result()["exit_code"] == 0
    assert (
        linux_guest.command(f"from pathlib import Path; print(Path({stage!r}).exists())").strip()
        == "False"
    )


def test_abandon_reclaims_stage_when_execution_setup_fails(linux_guest: LinuxGuest) -> None:
    stage = linux_guest.request("stage")["path"]
    assert linux_guest.request("abandon", path=stage) == {}
    result = linux_guest.request("exec", path=stage, exec_id="invalid", argv=["/bin/true"])
    assert result["errno"] == 22
    assert (
        linux_guest.command(f"from pathlib import Path; print(Path({stage!r}).exists())").strip()
        == "False"
    )
