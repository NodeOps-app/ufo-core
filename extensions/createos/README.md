# CreateOS sandbox carrier

One persistent CreateOS sandbox holds each conversation's workspace. The carrier uses async HTTPS
calls directly; the synchronous CreateOS Python SDK is not required. The API key stays on the host.

## Prepare a template

Build a Linux `ufo` client from this checkout, publish it at an HTTPS URL accessible to the template
builder, and record its SHA-256 digest. On Linux amd64 with Go 1.27.0 and Rust installed:

```bash
client/scripts/build-gh.sh x86_64-unknown-linux-musl /tmp/ufo-gh.gz
UFO_GH_ARCHIVE=/tmp/ufo-gh.gz cargo build --locked --release --manifest-path client/Cargo.toml
sha256sum client/target/release/ufo
```

Set `UFO_CREATEOS_API_KEY`, then build the template:

```bash
uv run python sandbox/build_createos_template.py \
  --name ufo \
  --client-url https://artifacts.example.com/ufo-linux \
  --client-sha256 <sha256>
```

| Template component | Purpose |
|---|---|
| Linux `ufo` binary | SHA-256, ELF CPU architecture, and executable version are checked. |
| Python, curl, Git, jq, ripgrep, CA certificates, util-linux | Shell/file operations and runtime setup. |
| `/opt/ufo-carrier/bin/python` with Pydantic 2.13.4 | Validates the same request/result models as the host. |
| uid/gid 1000; sudo removed | Unprivileged commands and file operations. |
| Root-owned skills directory, mode `0755` | Prevents member processes planting paths for trusted installers. |

CreateOS permits only its named base-image tags, not digest-pinned `FROM` values. Base and apt
package inputs are therefore not fully reproducible; the completed `tpl_` image is immutable.
Install any extra tools your extensions need, such as Node.js and Chromium, in the template.

## Configure

```toml
[sandbox]
backend = "createos"
image_ref = "tpl_<template-id>"
proxy_public_url = "https://egress.example.com"
```

| Host setting | Value |
|---|---|
| `UFO_CREATEOS_API_KEY` | Required; `CREATEOS_API_KEY` is also accepted. |
| `CREATEOS_SANDBOX_BASE_URL` | HTTPS API origin; defaults to `https://api.sb.createos.sh`. |
| `CREATEOS_SANDBOX_SHAPE` | Shape for new sandboxes; defaults to `s-2vcpu-2gb`. |

The `assistant` pack includes `createos`. Custom packs must name it explicitly. Start a new
conversation with `ufo --remote`; resumed conversations retain their existing carrier.

`proxy_public_url` must reach **ufo's egress proxy**, with a publicly trusted TLS certificate and
dedicated public IPv4 addresses and port. It is not the chat server URL. The carrier allows only
those destinations at sandbox creation and refreshes the policy and guest CA when opening a turn.
CreateOS treats an empty egress list as unrestricted; the carrier refuses an empty policy.

| Boundary | Behavior |
|---|---|
| Public ingress | Disabled and read back before preparing a turn. |
| Preview/browser tunnel | Provider hop uses API authentication; loopback listener trusts processes in the host network namespace. Run ufo in a namespace without untrusted local processes. |
| Commands and files | uid/gid 1000, with a fresh per-command proxy environment. |
| Trusted setup | Root; refuses writable or symlinked skills directories. |
| Lookup | Saved ID first; missing-ID recovery scans provider pages because the API offers no name filter. |
| Interactive PTY | Not provided. |

Stopping a turn records cancellation on the sandbox's protected disk before killing its cgroup.
The launch lock also checks this record, so delayed commands cannot start after Stop. The record
survives guest-helper restarts and cgroup cleanup for the lifetime of the sandbox.

Sandboxes idle for 30 minutes pause; reopening resumes them. Files survive pause and server
restart. When a saved sandbox is deleted or expires, the next execution opens a replacement from
the configured template and persists its new ID. Recovery reuses an existing conversation-named
replacement before creating one, including after a concurrent create conflict. Deleted workspace
files are not restored. Read-only attachment never provisions a replacement. Use CreateOS's
operator tools to manage or delete sandboxes.

## Validate

```bash
make test-one FILE=extensions/createos/tests/test_carrier.py
make test-one FILE=extensions/createos/tests/test_tunnel.py
make test-one FILE=extensions/createos/tests/test_template.py
uv run pytest -q extensions/createos/tests/test_guest.py
UFO_CREATEOS_TEST_TEMPLATE=tpl_<template-id> \
  uv run pytest -q extensions/createos/tests/integration/test_createos_carrier.py
```

Guest tests require Docker with privileged containers and private cgroup v2 namespaces. The opt-in
live test creates and deletes a sandbox. It checks
workspace persistence, command deadlines, files, permissions, private forwarding, pause/resume,
per-turn environments, cancellation, and blocked direct internet access. A complete deployment
also needs a model/tool call through its live ufo egress proxy to verify credential injection and
metering.
