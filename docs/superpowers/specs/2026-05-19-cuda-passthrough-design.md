# CUDA Passthrough Design (sandbox-runtime)

Date: 2026-05-19
Branch: gpu_support

## Summary

Add opt-in NVIDIA CUDA compute device passthrough to the Linux bubblewrap path of
`@anthropic-ai/sandbox-runtime`. Compute device nodes only. Off by default.
macOS is a no-op. Existing bwrap argument shape is unchanged when the flag is
absent or false. This port adapts the Codex `bwrap-cuda-sandbox-design` to this
repo's TypeScript/JSON configuration model.

## Goals

- Callers opt a `SandboxRuntimeConfig` into CUDA via `hardware.cuda = true`.
- Bind compute-only NVIDIA device nodes through bwrap; tolerate missing nodes
  using `--dev-bind-try` so non-GPU hosts remain usable.
- Expose a `detectCudaAvailable()` helper so library consumers (e.g. Claude
  Code) can decide whether to enable the flag.
- Keep behavior identical to today when `hardware.cuda` is unset or false.
- Provide arg-shape unit coverage plus a GPU-host smoke-test scaffold that
  skips cleanly on machines without `/dev/nvidiactl`.

## Non-Goals

- Do not enable GPU access by default.
- Do not expose display-oriented device nodes (`/dev/nvidia-modeset`,
  `/dev/dri/*`).
- Do not support Vulkan, OpenGL, AMD ROCm, or Intel GPUs in v1.
- Do not add a `/proc/driver/nvidia` bind in v1. Defer until smoke-test
  evidence demonstrates a CUDA init failure that points at missing procfs
  metadata.
- Do not modify the seccomp BPF filter or `apply-seccomp` behavior. The current
  filter blocks `socket(AF_UNIX, ...)` and io_uring syscalls only — CUDA's
  ioctl-based device control is unaffected. `apply-seccomp` remounts `/proc`
  but not `/dev`, so outer-bwrap device binds survive the nested mount
  namespace.
- Do not change the macOS Seatbelt profile.

## Configuration

`SandboxRuntimeConfig` gains an optional `hardware` block. Schema lives in
`src/sandbox/sandbox-config.ts` and is added to the Zod
`SandboxRuntimeConfigSchema`:

```ts
const HardwareConfigSchema = z
  .object({
    cuda: z.boolean().optional().default(false),
  })
  .optional()
```

Settings JSON example:

```json
{
  "network": { "allowedDomains": [], "deniedDomains": [] },
  "filesystem": { "allowWrite": ["."] },
  "hardware": { "cuda": true }
}
```

A missing `hardware` block is equivalent to `hardware.cuda = false`. The block
is portable between platforms; macOS ignores it without warning, matching the
established `allowUnixSockets` precedent (silently ignored on Linux per the
README).

The type is re-exported from `src/index.ts`:

```ts
export type { HardwareConfig } from './sandbox/sandbox-config.js'
```

Hot-reload via the existing `--control-fd` JSON-lines protocol accepts the new
field through `SandboxManager.updateConfig()`. Device discovery is cached at
initialization (hosts are not expected to hot-plug NVIDIA devices in
sandbox-runtime's use cases), and the cached list is gated by the flag at
wrap-time, so toggling `cuda` on/off post-init works.

## Runtime Model

No protocol layer in this repo equivalent to Codex's permission profiles. The
`hardware` block lives directly on `SandboxRuntimeConfig` and is read by the
Linux back-end during argument construction.

Device discovery runs once during sandbox initialization, in
`linux-sandbox-utils.ts` (alongside or just after
`initializeLinuxNetworkBridge`). Module-level state caches the discovered list
for the lifetime of the process. Re-running discovery is not required because
device topology does not change in expected deployments.

```ts
const FIXED_NODES = [
  '/dev/nvidiactl',
  '/dev/nvidia-uvm',
  '/dev/nvidia-uvm-tools',
  '/dev/nvidia-caps',
]

function discoverCudaDevices(): string[] {
  let indexed: string[] = []
  try {
    indexed = fs
      .readdirSync('/dev')
      .filter(n => /^nvidia\d+$/.test(n))
      .sort()
      .map(n => '/dev/' + n)
  } catch {
    // EACCES or other readdir failures on locked-down hosts are non-fatal.
    // Fixed nodes are still attempted via --dev-bind-try.
  }
  return [...FIXED_NODES, ...indexed]
}
```

## Bubblewrap Behavior

When `config.hardware?.cuda === true` and the platform is Linux,
`wrapCommandWithSandboxLinux` appends, after the baseline `--dev /dev` mount,
one `--dev-bind-try <host> <sandbox>` pair per cached device path:

```text
--dev-bind-try /dev/nvidiactl       /dev/nvidiactl
--dev-bind-try /dev/nvidia-uvm      /dev/nvidia-uvm
--dev-bind-try /dev/nvidia-uvm-tools /dev/nvidia-uvm-tools
--dev-bind-try /dev/nvidia-caps     /dev/nvidia-caps
--dev-bind-try /dev/nvidia0         /dev/nvidia0
... (further /dev/nvidia<N> nodes as discovered)
```

`--dev-bind-try` swallows missing-node errors, so a stale cache, a partial
host, or a node that disappeared between discovery and exec is non-fatal.

Excluded nodes (never bound, hard-coded out): `/dev/nvidia-modeset`, anything
under `/dev/dri/`. The exclusion is documented inline in the source.

## API Surface

Added to library exports in `src/index.ts`:

```ts
export { detectCudaAvailable } from './sandbox/linux-sandbox-utils.js'
export type { HardwareConfig } from './sandbox/sandbox-config.js'
```

`detectCudaAvailable()` returns `true` when the platform is Linux **and**
`/dev/nvidiactl` exists. Implementation is a single `fs.existsSync` call. It
does not `dlopen` libcuda — keeping the probe cheap and avoiding a new
runtime surface inside the host process. Consumers gate `hardware.cuda` on
this helper.

## Error Handling

- **Missing CUDA nodes when `cuda = true`:** silent; `--dev-bind-try` handles
  per-node absence; CUDA programs fail at their own runtime path. This matches
  the spec's "argument construction does not fail for optional device absence"
  guideline.
- **macOS with `cuda = true`:** schema accepts, the macOS code path ignores
  the field. No warning emitted.
- **`readdir('/dev')` failure during discovery:** caught, treated as empty
  indexed list. Fixed nodes still emitted via `--dev-bind-try`.
- **Non-x64/arm64 architectures:** orthogonal. Seccomp arch limitations are
  unchanged. If the user opts out of seccomp with `allowAllUnixSockets`, CUDA
  passthrough still works because the binds are mounted by outer bwrap.

## Testing

New file `test/sandbox/cuda-passthrough.test.ts` (Bun runner, `bun:test`):

- `cuda` absent → generated bwrap argv contains no `nvidia` substring.
- `cuda: false` → generated bwrap argv contains no `nvidia` substring.
- `cuda: true` on Linux → argv contains `--dev-bind-try /dev/nvidiactl /dev/nvidiactl`.
- `cuda: true` on Linux → argv contains `--dev-bind-try /dev/nvidia-uvm /dev/nvidia-uvm`
  and `--dev-bind-try /dev/nvidia-uvm-tools /dev/nvidia-uvm-tools`.
- `cuda: true` → argv does not contain `nvidia-modeset` or `/dev/dri`.
- `cuda: true` with stubbed empty `/dev` readdir → emits only the four fixed
  nodes; no throw.
- `cuda: true` on macOS → generated Seatbelt profile contains no nvidia
  references (skip on Linux).

Extend `test/config-validation.test.ts`:

- `{ hardware: { cuda: true } }` parses successfully.
- Missing `hardware` parses successfully (default behavior).
- `{ hardware: { cuda: "yes" } }` fails Zod validation.
- `{ hardware: { cuda: false } }` parses and matches no-block default.

New scaffold `test/sandbox/cuda-smoke.test.ts`:

- `describe.skipIf(!isLinux() || !existsSync('/dev/nvidiactl'))`.
- Runs `srt -c 'nvidia-smi -L'` (or a minimal C program if `nvidia-smi` is not
  installed) under a config with `hardware.cuda = true`. Asserts exit 0 and
  stdout matches `/GPU/`.
- If the smoke test fails specifically because NVIDIA proc metadata is
  missing, the failure message instructs the developer to file a follow-up
  amendment proposing a read-only `/proc/driver/nvidia` mount, backed by that
  evidence.

CI: the existing Linux integration-tests jobs in
`.github/workflows/integration-tests.yml` do not have GPU runners, so the
smoke test will skip cleanly. No CI workflow change is required for v1.

## Documentation

- `README.md`: new "GPU access (Linux)" section under the Configuration
  reference. Includes a JSON example, the exact list of bound device nodes,
  the explicit exclusions, a pointer to `detectCudaAvailable()`, and a
  security note that CUDA driver passthrough expands the kernel attack
  surface and should only be enabled when the workload needs it.
- `CLAUDE.md`: one-line mention in the "Platform back-ends > Linux" paragraph
  noting the optional GPU passthrough path.

## Implementation Boundaries

Primary code areas:

- `src/sandbox/sandbox-config.ts` — `HardwareConfigSchema`, `HardwareConfig`
  type, integration into `SandboxRuntimeConfigSchema`.
- `src/sandbox/linux-sandbox-utils.ts` — `discoverCudaDevices()`, module-level
  cache, `detectCudaAvailable()`, CUDA bind emission inside
  `wrapCommandWithSandboxLinux`.
- `src/sandbox/macos-sandbox-utils.ts` — verification only; ensures the
  Seatbelt profile generator does not branch on `hardware`.
- `src/index.ts` — re-export `HardwareConfig` and `detectCudaAvailable`.
- `test/sandbox/cuda-passthrough.test.ts` — new file (arg-shape coverage).
- `test/sandbox/cuda-smoke.test.ts` — new file (GPU-gated runtime probe).
- `test/config-validation.test.ts` — extend with `hardware` block cases.
- `README.md` — new GPU section.
- `CLAUDE.md` — architecture note.

Out of scope, deferred:

- `/proc/driver/nvidia` mount — gated on smoke-test evidence.
- `/dev/dri` and render-node support — separate future design.
- Non-NVIDIA GPU vendors — separate future design.
