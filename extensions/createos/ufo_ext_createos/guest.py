import errno
import fcntl
import hashlib
import json
import os
import pwd
import shutil
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from functools import partial
from pathlib import Path
from uuid import UUID, uuid4

USER_ID = 1000
GROUP_ID = 1000
STAGE_ROOT = Path("/var/lib/ufo-carrier")
HOME_ROOT = Path("/home/user")
CGROUP_ROOT = Path("/sys/fs/cgroup/ufo-carrier")
COPY_CHUNK_SIZE = 1024 * 1024


@dataclass(frozen=True)
class Request:
    action: str
    conversation_id: str = ""
    ca_cert: str = ""
    hosts: str = ""
    path: str = ""
    input_path: str = ""
    output_path: str = ""
    argv: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    timeout_s: float = 60
    turn_id: str = ""
    exec_id: str = ""
    privileged: bool = False


@dataclass(frozen=True)
class Guest:
    request: Request

    def run(self) -> dict[str, str | int | float | None]:
        """Execute one trusted host request inside the sandbox."""
        if os.geteuid() != 0:
            raise PermissionError(errno.EPERM, "carrier requires root")
        match self.request.action:
            case "prepare":
                self._root_directory(STAGE_ROOT, 0o700)
                with (STAGE_ROOT / "prepare.lock").open("a") as lock:
                    fcntl.flock(lock, fcntl.LOCK_EX)
                    return self._prepare()
            case "stage":
                self._root_directory(STAGE_ROOT, 0o700)
                path = STAGE_ROOT / uuid4().hex
                path.mkdir(mode=0o700)
                return {"path": str(path)}
            case "exec":
                stage = self._stage(self.request.path)
                try:
                    return self._exec()
                finally:
                    with (STAGE_ROOT / "prepare.lock").open("a") as lock:
                        fcntl.flock(lock, fcntl.LOCK_EX)
                        (stage / "done").touch()
                        if (stage / "abandoned").exists():
                            shutil.rmtree(stage)
            case "abandon":
                with (STAGE_ROOT / "prepare.lock").open("a") as lock:
                    fcntl.flock(lock, fcntl.LOCK_EX)
                    stage = self._stage(self.request.path, missing_ok=True)
                    if stage.exists():
                        (stage / "abandoned").touch()
                        if (stage / "done").exists():
                            shutil.rmtree(stage)
            case "stop":
                self._stop()
            case "write":
                self._write()
            case "read":
                self._read()
            case "cleanup":
                with (STAGE_ROOT / "prepare.lock").open("a") as lock:
                    fcntl.flock(lock, fcntl.LOCK_EX)
                    stage = self._stage(self.request.path, missing_ok=True)
                    if stage.exists():
                        shutil.rmtree(stage)
            case _:
                raise ValueError("unknown guest action")
        return {}

    def _prepare(self) -> dict[str, str | int | float | None]:
        user = pwd.getpwuid(USER_ID)
        if user.pw_gid != GROUP_ID or user.pw_dir != str(HOME_ROOT):
            raise ValueError("sandbox user must have uid/gid 1000 and /home/user home")
        binary = Path("/usr/local/bin/ufo")
        if not binary.is_file() or not os.access(binary, os.X_OK):
            raise FileNotFoundError(errno.ENOENT, "sandbox image requires /usr/local/bin/ufo")
        for path in (HOME_ROOT, HOME_ROOT / ".ufo", HOME_ROOT / ".ufo/runs"):
            self._root_directory(path, 0o755)
        runtime = HOME_ROOT / ".ufo/runs" / UUID(self.request.conversation_id).hex
        try:
            runtime.mkdir(mode=0o700)
        except FileExistsError:
            metadata = runtime.lstat()
            if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != USER_ID:
                raise PermissionError(errno.EPERM, "unsafe runtime directory") from None
        else:
            os.chown(runtime, USER_ID, GROUP_ID)
        self._root_directory(STAGE_ROOT, 0o700)
        Path("/usr/local/share/ca-certificates/ufo-proxy.crt").write_text(self.request.ca_cert)
        subprocess.run(["update-ca-certificates"], check=True, stdout=subprocess.DEVNULL)
        hosts = Path("/etc/hosts")
        entries = [
            line for line in hosts.read_text().splitlines() if not line.endswith("# ufo-egress")
        ]
        entries.extend(line + " # ufo-egress" for line in self.request.hosts.splitlines() if line)
        hosts.write_text("\n".join(entries) + "\n")
        return {"runtime_root": str(runtime)}

    def _root_directory(self, path: Path, mode: int) -> None:
        try:
            path.mkdir(mode=mode)
        except FileExistsError:
            pass
        metadata = path.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
            raise PermissionError(errno.EPERM, f"unsafe carrier directory: {path}")

    def _stage(self, value: str, *, missing_ok: bool = False) -> Path:
        path = Path(value)
        if path.parent != STAGE_ROOT or UUID(path.name).hex != path.name:
            raise PermissionError(errno.EPERM, "invalid stage path")
        self._root_directory(STAGE_ROOT, 0o700)
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            if missing_ok:
                return path
            raise
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o077:
            raise PermissionError(errno.EPERM, "unsafe stage directory")
        return path

    def _exec(self) -> dict[str, str | int | float | None]:
        stage = self._stage(self.request.path)
        if not self.request.exec_id or self.request.timeout_s <= 0:
            raise ValueError("exec requires an identifier and a positive timeout")
        stdout_path = stage / "stdout"
        stderr_path = stage / "stderr"
        timed_out: float | None = None
        with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
            with (STAGE_ROOT / "prepare.lock").open("a") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                self._root_directory(CGROUP_ROOT, 0o700)
                self._prune_groups()
                turn = CGROUP_ROOT / hashlib.sha256(self.request.turn_id.encode()).hexdigest()
                self._root_directory(turn, 0o700)
                group = turn / UUID(self.request.exec_id).hex
                group.mkdir(mode=0o700)
                try:
                    child = subprocess.Popen(
                        self.request.argv,
                        cwd="/workspace",
                        env=self.request.env,
                        stdin=subprocess.DEVNULL,
                        stdout=stdout,
                        stderr=stderr,
                        start_new_session=True,
                        preexec_fn=partial(self._enter_group, group),
                    )
                except (FileNotFoundError, PermissionError) as error:
                    exit_code = 127 if error.errno == errno.ENOENT else 126
                    stderr.write(str(error).encode())
                    child = None
            if child is not None:
                try:
                    exit_code = child.wait(timeout=self.request.timeout_s)
                except subprocess.TimeoutExpired:
                    timed_out = self.request.timeout_s
                    with (STAGE_ROOT / "prepare.lock").open("a") as lock:
                        fcntl.flock(lock, fcntl.LOCK_EX)
                        if group.exists():
                            (group / "cgroup.kill").write_text("1")
                    child.wait()
                    exit_code = 124
            with (STAGE_ROOT / "prepare.lock").open("a") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                self._prune_groups()
        return {
            "path": str(stage),
            "stdout_path": str(stdout_path),
            "stderr_path": str(stderr_path),
            "exit_code": exit_code,
            "timed_out_after_s": timed_out,
        }

    def _enter_group(self, group: Path) -> None:
        (group / "cgroup.procs").write_text(str(os.getpid()))
        if self.request.privileged:
            os.setgroups([])
        else:
            self._drop_privileges()

    def _prune_groups(self) -> None:
        for turn in CGROUP_ROOT.iterdir():
            if not turn.is_dir():
                continue
            for group in turn.iterdir():
                if not group.is_dir():
                    continue
                if "populated 0" in (group / "cgroup.events").read_text().splitlines():
                    group.rmdir()
            if "populated 0" in (turn / "cgroup.events").read_text().splitlines():
                turn.rmdir()

    def _stop(self) -> None:
        if not self.request.turn_id:
            raise ValueError("stop requires a turn identifier")
        self._root_directory(STAGE_ROOT, 0o700)
        with (STAGE_ROOT / "prepare.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            self._root_directory(CGROUP_ROOT, 0o700)
            turn = CGROUP_ROOT / hashlib.sha256(self.request.turn_id.encode()).hexdigest()
            if turn.exists():
                (turn / "cgroup.kill").write_text("1")
            self._prune_groups()

    def _write(self) -> None:
        source = Path(self.request.input_path)
        self._stage(str(source.parent))
        with source.open("rb") as incoming:
            self._drop_privileges()
            target = Path(self.request.path)
            target.parent.mkdir(parents=True, exist_ok=True)
            try:
                mode = stat.S_IMODE(target.stat().st_mode)
            except FileNotFoundError:
                mode = 0o644
            descriptor, temporary = tempfile.mkstemp(dir=target.parent)
            try:
                with os.fdopen(descriptor, "wb") as outgoing:
                    shutil.copyfileobj(incoming, outgoing, COPY_CHUNK_SIZE)
                    os.fchmod(outgoing.fileno(), mode)
                Path(temporary).replace(target)
            finally:
                Path(temporary).unlink(missing_ok=True)

    def _read(self) -> None:
        destination = Path(self.request.output_path)
        self._stage(str(destination.parent))
        with destination.open("xb") as outgoing:
            self._drop_privileges()
            with Path(self.request.path).open("rb") as incoming:
                shutil.copyfileobj(incoming, outgoing, COPY_CHUNK_SIZE)

    def _drop_privileges(self) -> None:
        os.setgroups([])
        os.setgid(GROUP_ID)
        os.setuid(USER_ID)


if __name__ == "__main__":
    try:
        print(json.dumps(Guest(Request(**json.load(sys.stdin))).run()))
    except OSError as error:
        print(json.dumps({"error": str(error), "errno": error.errno}))
    except (ValueError, TypeError) as error:
        print(json.dumps({"error": str(error), "errno": errno.EINVAL}))
