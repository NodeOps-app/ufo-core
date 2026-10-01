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
| Python and `python3-venv` | Runs the guest helper in an isolated dependency environment. |
| curl and CA certificates | Downloads the verified client and trusts the egress proxy. |
| Git, jq, ripgrep, util-linux | Supplies shell tools and process/runtime utilities. |
| `/opt/ufo-carrier/bin/python` | Pydantic and all dependencies use versions and wheel hashes from `uv.lock`; pip requires hashes. |
| uid/gid 1000; sudo removed | Runs member commands without a path to root through sudo. |
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
| Command output | Each stdout/stderr download is limited to 16 MiB; overflow fails instead of returning incomplete output. |
| Trusted setup | Root; refuses writable or symlinked skills directories. |
| Lookup | Saved ID first; missing-ID recovery scans provider pages because the API offers no name filter. |
| Interactive PTY | Not provided. |

| Lifecycle | Behavior |
|---|---|
| Stop | Resumes a paused sandbox, verifies ownership, then records cancellation under the launch lock before killing its cgroup. |
| Stopped turn | Subsequent exec, read, and write requests carrying that turn ID are refused. Off-turn file browsing remains available. |
| Stop records | One empty file per stopped turn, retained for the sandbox lifetime. No finite deletion age is safe without a bound on delayed requests. |
| Idle sandbox | Pauses after 30 minutes; reopening resumes it with files intact. |
| Missing saved sandbox | Reuses a conversation-named replacement or creates one, records an operator warning, and persists the new ID. Deleted files cannot be restored. |
| Read-only attachment | Returns no handle for missing or differently owned sandboxes; never provisions. |
| Incompatible template | Refuses unsafe skills directories or a missing guest runtime. Preserve workspace files using CreateOS operator tools before replacing the sandbox with a compatible template. Never deletes files to repair preparation. |

## Validate

```bash
make test-one FILE=extensions/createos/tests/test_carrier.py
make test-one FILE=extensions/createos/tests/test_tunnel.py
make test-one FILE=extensions/createos/tests/test_template.py
make test-one FILE=extensions/createos/tests/test_messages.py
uv run pytest -q extensions/createos/tests/test_guest.py
UFO_CREATEOS_TEST_TEMPLATE=tpl_<template-id> \
  uv run pytest -q extensions/createos/tests/integration/test_createos_carrier.py
```

Guest tests run the host against the real helper and install its hash-locked dependencies. They
require Docker with privileged containers and private cgroup v2 namespaces, and run in the existing
integration CI job. The opt-in live test creates and deletes a sandbox. It checks workspace
persistence, command deadlines, files, permissions, private forwarding, pause/resume,
per-turn environments, cancellation, and blocked direct internet access. A complete deployment
also needs a model/tool call through its live ufo egress proxy to verify credential injection and
metering.
