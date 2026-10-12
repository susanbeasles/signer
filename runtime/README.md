# Installed signing runtime

This source implements the fixed 1Password CLI → private pipe → ephemeral
`ssh-agent` → `ssh-keygen -Y sign -U -n git` path. It exposes no raw signing HTTP
API. The service authorizes an exact Git object and consumes its retained effect
before the runtime reads the immutable 1Password field. Every asynchronous step
rechecks the action/proof deadline. Each signing call gets its own agent; only
the pinned Ed25519 public key is accepted from that agent. Verification and proof
reads never obtain the private key.

The commissioned image runs `node runtime/container-server.mjs` as container PID1.
It must install `/opt/signing-control/config/runtime.json` containing exactly
`{services,runtime}`. The services array contains 1–32 exact approved repository profiles, with unique repository IDs and names; every profile uses the same pinned signer. Each per-job service must equal one complete profile. One reviewed image can therefore serve the seven approved repositories without rebuilding or changing its configuration between jobs. This public configuration pins the immutable vault/item
reference, SSH public key/fingerprint, four executable paths and SHA-256 digests,
and explicit approved 1Password HTTPS origins. The controller supplies the full
`{service,runtime,platform}` configuration and a digest-bound job, independently
checks the actual image digest, and uses private container networking. Keeping
the image digest outside the image-resident configuration avoids a self-referential
image hash.

`runtime/Dockerfile` is the source-only image recipe. Its required build inputs
are `SIGNING_BASE_IMAGE` (an approved registry reference with `@sha256:…`),
`SIGNING_NODE_SHA256`, `SIGNING_SETPRIV_SHA256`, and the reviewed public
`image-runtime-config.json` at the context root. The base must already contain
the tools; the recipe performs no installation. The build verifier checks those
pins and every op/OpenSSH/Git executable digest. The fixed `setpriv` entrypoint
clears all capabilities, groups and privilege escalation before execing Node as
UID/GID 10001. Startup checks the resulting identity, PID1, core limit, swap and
tmpfs and refuses readiness when they differ. No image build or pull was run.

`GET /ready` returns 204 before the single lifetime reservation. The private
`POST /v1/execute` accepts exactly `{job,config,serviceAccountToken,callbackToken}`.
The reservation happens before reading the request body. Malformed, expired,
incomplete and concurrent handoffs cannot reopen it. The supervisor receives
only `{job,config}` on stdin, the optional op token on private FD3, and the callback
capability on private FD4. Tokens never appear in arguments or the supervisor's
environment. Only the fixed op child receives `OP_SERVICE_ACCOUNT_TOKEN`.

The supervisor calls the fixed source service and sends one completed/uncertain
callback to `https://signing-control.internal/v1/jobs/complete`. A lost response is
not retried. Stdout is limited to a nonsecret `{jobId,state}` receipt. The server
terminates after the supervisor exits; the controller retains the outcome and
independently destroys and inspects the container before releasing its lock.

Temporary agent sockets, op state, public verification files and public key files
use private tmpfs directories. The private key is passed directly between bounded
process pipes and the agent; it is never written to a private-key file. Buffer
copies are zeroed after use; JavaScript strings and OS pipe buffers remain subject
to their respective runtimes' lifetimes. No application code runs in this image.

Activation still requires an approved service-only 1Password binding, existing
key/public fingerprint and registration, reviewed executable hashes and exact
op origins, immutable source policy and private capabilities, and platform
qualification. In particular, core dumps must be disabled before the HTTP
handoff, swap must be disabled, `/dev/shm` must be tmpfs, the Cloudflare intercept
CA must be trusted without TLS bypass, and container PID1 exit/destruction must
kill every descendant in its cgroup. JS timeout/signal cleanup alone cannot
guarantee cleanup after SIGKILL or host failure. None of those live qualifications
has been performed here.

Node uses the fixed injected CA through `NODE_EXTRA_CA_CERTS`; the op child gets
the same path through `SSL_CERT_FILE`, supported by
[Go's system certificate pool](https://pkg.go.dev/crypto/x509#SystemCertPool).
Compatibility of the actual pinned op distribution with Cloudflare interception
still requires an authorized fixture qualification; this source test is not that
qualification.

Run `node --test test/runtime-signer.test.mjs test/runtime-container.test.mjs`.
The tests use an in-memory, synthetic Ed25519 fixture and an injected fake op
response. They exercise installed local OpenSSH tools and private child-process
FDs. They never call op, retrieve a real key, register a key, contact a provider,
or publish source.
