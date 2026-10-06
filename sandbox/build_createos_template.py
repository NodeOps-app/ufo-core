"""Publish a CreateOS template containing a checksum-pinned Linux ufo client."""

import argparse
import shlex
import tomllib
from dataclasses import dataclass
from pathlib import Path
from time import monotonic, sleep
from typing import Literal
from urllib.parse import urlsplit

import httpx
from pydantic import BaseModel, Field, field_validator

from ufo.sdk.credentials import deploy_env

DEFAULT_BASE_URL = "https://api.sb.createos.sh"
BUILD_TIMEOUT_SECONDS = 1800
POLL_SECONDS = 5
REQUEST_TIMEOUT_SECONDS = 30
MAX_DOCKERFILE_BYTES = 64 * 1024
GUEST_PACKAGES = frozenset(
    {"pydantic", "pydantic-core", "annotated-types", "typing-extensions", "typing-inspection"}
)


class LockedDependency(BaseModel):
    name: str


class LockedWheel(BaseModel):
    hash: str


class LockedPackage(BaseModel):
    name: str
    version: str
    dependencies: list[LockedDependency] = []
    wheels: list[LockedWheel] = []


class Lockfile(BaseModel):
    package: list[LockedPackage]


def guest_requirements() -> str:
    """Read exact guest dependency versions and wheel hashes from the project's lockfile."""
    lock = Lockfile.model_validate(
        tomllib.loads(Path(__file__).parents[1].joinpath("uv.lock").read_text())
    )
    packages = {package.name: package for package in lock.package if package.name in GUEST_PACKAGES}
    if packages.keys() != GUEST_PACKAGES:
        raise ValueError("guest dependencies are missing from uv.lock")
    lines = []
    for name, package in sorted(packages.items()):
        if not package.wheels or any(dep.name not in packages for dep in package.dependencies):
            raise ValueError(f"guest dependency {name} is not fully locked")
        hashes = " ".join(f"--hash={wheel.hash}" for wheel in package.wheels)
        lines.append(f"{name}=={package.version} {hashes}")
    return "\n".join(lines) + "\n"


class TemplateSource(BaseModel):
    name: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,62}$")
    client_url: str
    client_sha256: str = Field(pattern=r"^[a-fA-F0-9]{64}$")

    @field_validator("client_url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        """Require an HTTPS artifact URL without embedded credentials or control characters."""
        parsed = urlsplit(value)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
            or any(ord(character) <= 32 or ord(character) == 127 for character in value)
        ):
            raise ValueError("client URL must be HTTPS without credentials or whitespace")
        return value

    def dockerfile(self) -> str:
        """Render the provider's restricted Dockerfile with root-owned runtime boundaries."""
        return "\n".join(
            (
                "FROM nodeops/sandbox:debian",
                "USER root",
                "RUN apt-get update && apt-get install -y --no-install-recommends "
                "python3 python3-venv curl ca-certificates git jq ripgrep util-linux "
                "&& apt-get purge -y sudo && rm -rf /etc/sudoers /etc/sudoers.d "
                "/var/lib/apt/lists/*",
                "RUN python3 -m venv /opt/ufo-carrier && printf '%b' "
                + shlex.quote(guest_requirements().replace("\n", "\\n"))
                + " | /opt/ufo-carrier/bin/pip install --no-cache-dir --require-hashes "
                "--only-binary=:all: -r /dev/stdin",
                "RUN curl --fail --silent --show-error --location --proto '=https' "
                "--proto-redir '=https' "
                f"{shlex.quote(self.client_url)} -o /usr/local/bin/ufo "
                f"&& printf '%s\\n' '{self.client_sha256.lower()}  /usr/local/bin/ufo' "
                "| sha256sum --check --strict - && chmod 0755 /usr/local/bin/ufo "
                "&& python3 -c 'import pathlib,platform,struct; "
                'h=pathlib.Path("/usr/local/bin/ufo").read_bytes()[:20]; '
                'assert h[:6]==b"\\x7fELF\\x02\\x01", "expected ELF64 little-endian binary"; '
                'assert struct.unpack("<H",h[18:20])[0]=='
                '{"x86_64":62,"aarch64":183}[platform.machine()], "wrong CPU architecture"\' '
                "&& /usr/local/bin/ufo --version",
                "RUN groupadd --gid 1000 user && useradd --uid 1000 --gid 1000 "
                "--home-dir /home/user --shell /bin/bash --no-create-home user "
                "&& install -d -o root -g root -m 0755 /home/user /home/user/.ufo "
                "/home/user/.ufo/runs "
                "&& install -d -o 1000 -g 1000 -m 0755 /workspace "
                "&& install -d -o root -g root -m 0755 /home/user/.ufo/skills "
                "&& install -d -o root -g root -m 0700 /var/lib/ufo-carrier "
                "&& install -o 1000 -g 1000 -m 0600 /dev/null /home/user/.ufo/session",
                "WORKDIR /workspace",
                "",
            )
        )


class TemplateView(BaseModel):
    id: str = Field(pattern=r"^tpl_[0-9A-Za-z]+$")
    status: Literal["pending", "building", "ready", "failed"]


class TemplateResponse(BaseModel):
    status: Literal["success"]
    data: TemplateView


@dataclass(frozen=True)
class TemplatePublisher:
    client: httpx.Client

    def publish(self, source: TemplateSource) -> str:
        """Submit one template and wait within a bounded external build deadline."""
        dockerfile = source.dockerfile()
        if len(dockerfile.encode()) > MAX_DOCKERFILE_BYTES:
            raise ValueError("CreateOS template Dockerfile exceeds 64 KiB")
        response = self.client.post(
            "/v1/templates", json={"name": source.name, "dockerfile": dockerfile}
        )
        response.raise_for_status()
        template = TemplateResponse.model_validate_json(response.content).data
        deadline = monotonic() + BUILD_TIMEOUT_SECONDS
        while template.status != "ready":
            if template.status == "failed":
                raise RuntimeError(f"CreateOS template {template.id} failed to build")
            remaining = deadline - monotonic()
            if remaining <= 0:
                raise TimeoutError(f"CreateOS template {template.id} build exceeded its deadline")
            sleep(min(POLL_SECONDS, remaining))
            response = self.client.get(f"/v1/templates/{template.id}")
            response.raise_for_status()
            template = TemplateResponse.model_validate_json(response.content).data
        return template.id


def main() -> None:
    """Publish an operator-configured template and print its immutable ID."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--name", required=True)
    parser.add_argument("--client-url", required=True)
    parser.add_argument("--client-sha256", required=True)
    source = TemplateSource.model_validate(vars(parser.parse_args()))
    api_key = deploy_env("CREATEOS_API_KEY")
    if not api_key:
        raise ValueError("UFO_CREATEOS_API_KEY or CREATEOS_API_KEY is required")
    base_url = deploy_env("CREATEOS_SANDBOX_BASE_URL") or DEFAULT_BASE_URL
    parsed = urlsplit(base_url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or any(ord(character) <= 32 or ord(character) == 127 for character in base_url)
    ):
        raise ValueError("CreateOS API URL must be HTTPS without credentials or query parameters")
    with httpx.Client(
        base_url=base_url,
        headers={"X-Api-Key": api_key},
        timeout=REQUEST_TIMEOUT_SECONDS,
        follow_redirects=False,
        trust_env=False,
    ) as client:
        print(TemplatePublisher(client).publish(source))


if __name__ == "__main__":
    main()
