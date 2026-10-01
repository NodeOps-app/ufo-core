import json
import shlex
import tomllib
from pathlib import Path

import httpx
import pytest
from pydantic import ValidationError

from sandbox.build_createos_template import (
    GUEST_PACKAGES,
    MAX_DOCKERFILE_BYTES,
    TemplatePublisher,
    TemplateResponse,
    TemplateSource,
    guest_requirements,
)

CLIENT_URL = "https://downloads.example.com/ufo-linux"
CLIENT_SHA256 = "abcdef0123456789" * 4


def test_template_uses_supported_instructions_and_verifies_download() -> None:
    source = TemplateSource(name="ufo", client_url=CLIENT_URL, client_sha256=CLIENT_SHA256)
    dockerfile = source.dockerfile()
    assert dockerfile.splitlines()[0] == "FROM nodeops/sandbox:debian"
    assert {line.split()[0] for line in dockerfile.splitlines()} <= {
        "FROM",
        "USER",
        "RUN",
        "WORKDIR",
    }
    download = next(line for line in dockerfile.splitlines() if line.startswith("RUN curl"))
    assert CLIENT_URL in shlex.split(download)
    assert f"{CLIENT_SHA256}  /usr/local/bin/ufo" in shlex.split(download)
    assert "sha256sum --check --strict - && chmod 0755 /usr/local/bin/ufo" in download
    assert "--proto '=https' --proto-redir '=https'" in download


def test_template_keeps_runtime_ancestors_root_owned_and_workspace_writable() -> None:
    dockerfile = TemplateSource(
        name="ufo", client_url=CLIENT_URL, client_sha256=CLIENT_SHA256
    ).dockerfile()
    assert "--uid 1000 --gid 1000" in dockerfile
    assert "-o root -g root -m 0755 /home/user /home/user/.ufo /home/user/.ufo/runs" in dockerfile
    assert "-o 1000 -g 1000 -m 0755 /workspace" in dockerfile
    assert "-o root -g root -m 0755 /home/user/.ufo/skills" in dockerfile
    assert "-o root -g root -m 0700 /var/lib/ufo-carrier" in dockerfile
    assert "-o 1000 -g 1000 -m 0600 /dev/null /home/user/.ufo/session" in dockerfile
    assert "apt-get purge -y sudo" in dockerfile
    assert "/opt/ufo-carrier/bin/pip install --no-cache-dir --require-hashes" in dockerfile
    assert "wrong CPU architecture" in dockerfile
    assert "/usr/local/bin/ufo --version" in dockerfile


def test_artifact_url_is_one_shell_argument() -> None:
    url = "https://downloads.example.com/ufo?token=a'b&filename=$(whoami)"
    dockerfile = TemplateSource(
        name="ufo", client_url=url, client_sha256=CLIENT_SHA256
    ).dockerfile()
    download = next(line for line in dockerfile.splitlines() if line.startswith("RUN curl"))
    assert url in shlex.split(download)


@pytest.mark.parametrize(
    "url",
    [
        "http://downloads.example.com/ufo",
        "https://user:password@example.com/ufo",
        "https:///ufo",
        "https://example.com/ufo\nRUN malicious",
        "https://example.com/ufo#fragment",
        "https://example.com/ufo\x00",
    ],
)
def test_template_rejects_unsafe_artifact_urls(url: str) -> None:
    with pytest.raises(ValidationError):
        TemplateSource(name="ufo", client_url=url, client_sha256=CLIENT_SHA256)


@pytest.mark.parametrize("checksum", ["", "a" * 63, "g" * 64, "a" * 64 + "\n"])
def test_template_requires_complete_sha256(checksum: str) -> None:
    with pytest.raises(ValidationError):
        TemplateSource(name="ufo", client_url=CLIENT_URL, client_sha256=checksum)


@pytest.mark.parametrize("name", ["", "-ufo", "UFO", "a" * 64, "ufo\nRUN malicious"])
def test_template_rejects_invalid_names(name: str) -> None:
    with pytest.raises(ValidationError):
        TemplateSource(name=name, client_url=CLIENT_URL, client_sha256=CLIENT_SHA256)


def test_template_response_requires_known_state_and_immutable_id() -> None:
    assert (
        TemplateResponse.model_validate(
            {"status": "success", "data": {"id": "tpl_abc123", "status": "ready"}}
        ).data.id
        == "tpl_abc123"
    )
    with pytest.raises(ValidationError):
        TemplateResponse.model_validate(
            {"status": "success", "data": {"id": "ufo", "status": "ready"}}
        )
    with pytest.raises(ValidationError):
        TemplateResponse.model_validate(
            {"status": "success", "data": {"id": "tpl_abc123", "status": "unknown"}}
        )


def test_publish_submits_rendered_template_and_polls_until_ready(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("sandbox.build_createos_template.POLL_SECONDS", 0)
    states = iter(("pending", "building", "ready"))
    source = TemplateSource(name="ufo", client_url=CLIENT_URL, client_sha256=CLIENT_SHA256)

    def respond(request: httpx.Request) -> httpx.Response:
        state = next(states)
        if state == "pending":
            assert request.method == "POST"
            assert request.url.path == "/v1/templates"
            assert json.loads(request.content) == {
                "name": "ufo",
                "dockerfile": source.dockerfile(),
            }
        else:
            assert request.method == "GET"
            assert request.url.path == "/v1/templates/tpl_abc123"
        return httpx.Response(
            200, json={"status": "success", "data": {"id": "tpl_abc123", "status": state}}
        )

    with httpx.Client(
        base_url="https://api.example.com", transport=httpx.MockTransport(respond)
    ) as client:
        assert TemplatePublisher(client).publish(source) == "tpl_abc123"


def test_publish_reports_failed_build(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sandbox.build_createos_template.POLL_SECONDS", 0)

    def respond(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "status": "success",
                "data": {
                    "id": "tpl_abc123",
                    "status": "pending" if request.method == "POST" else "failed",
                },
            },
        )

    source = TemplateSource(name="ufo", client_url=CLIENT_URL, client_sha256=CLIENT_SHA256)
    with (
        httpx.Client(
            base_url="https://api.example.com", transport=httpx.MockTransport(respond)
        ) as client,
        pytest.raises(RuntimeError, match="tpl_abc123 failed to build"),
    ):
        TemplatePublisher(client).publish(source)


@pytest.mark.parametrize("failure_method", ["POST", "GET"])
def test_publish_surfaces_http_failure(
    monkeypatch: pytest.MonkeyPatch, failure_method: str
) -> None:
    monkeypatch.setattr("sandbox.build_createos_template.POLL_SECONDS", 0)

    def respond(request: httpx.Request) -> httpx.Response:
        if request.method == failure_method:
            return httpx.Response(503, json={"status": "error", "message": "unavailable"})
        return httpx.Response(
            200,
            json={"status": "success", "data": {"id": "tpl_abc123", "status": "pending"}},
        )

    source = TemplateSource(name="ufo", client_url=CLIENT_URL, client_sha256=CLIENT_SHA256)
    with (
        httpx.Client(
            base_url="https://api.example.com", transport=httpx.MockTransport(respond)
        ) as client,
        pytest.raises(httpx.HTTPStatusError) as error,
    ):
        TemplatePublisher(client).publish(source)
    assert error.value.response.status_code == 503


def test_publish_rejects_oversized_utf8_dockerfile_before_sending() -> None:
    source = TemplateSource(
        name="ufo",
        client_url=CLIENT_URL + "?token=" + "é" * (MAX_DOCKERFILE_BYTES // 2),
        client_sha256=CLIENT_SHA256,
    )
    assert len(source.dockerfile()) < MAX_DOCKERFILE_BYTES
    assert len(source.dockerfile().encode()) > MAX_DOCKERFILE_BYTES

    def refuse_request(request: httpx.Request) -> httpx.Response:
        pytest.fail(f"oversized Dockerfile sent to {request.url.path}")

    with (
        httpx.Client(
            base_url="https://api.example.com", transport=httpx.MockTransport(refuse_request)
        ) as client,
        pytest.raises(ValueError, match="exceeds 64 KiB"),
    ):
        TemplatePublisher(client).publish(source)


def test_guest_requirements_pin_every_dependency_and_hash_from_uv_lock() -> None:
    lock = tomllib.loads(Path("uv.lock").read_text())
    packages = {p["name"]: p for p in lock["package"] if p["name"] in GUEST_PACKAGES}
    requirements = guest_requirements().splitlines()
    assert len(requirements) == len(GUEST_PACKAGES)
    for line in requirements:
        pinned, *hashes = line.split()
        name, version = pinned.split("==")
        assert version == packages[name]["version"]
        assert set(hashes) == {"--hash=" + wheel["hash"] for wheel in packages[name]["wheels"]}
        assert {dep["name"] for dep in packages[name].get("dependencies", [])} <= packages.keys()
