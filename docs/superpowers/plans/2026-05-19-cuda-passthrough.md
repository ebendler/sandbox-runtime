# CUDA Passthrough Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add opt-in NVIDIA CUDA compute-device passthrough to the Linux bubblewrap path of `@anthropic-ai/sandbox-runtime`, gated by `hardware.cuda` config, with `--dev-bind-try` of compute-only NVIDIA device nodes.

**Architecture:** New optional `hardware` block in the Zod schema. `SandboxManager.initialize()` calls `discoverCudaDevices()` once on Linux and caches the resulting list. Per wrap-call, the Linux back-end receives `cudaEnabled` + `cudaDevices` through `LinuxSandboxParams` and appends `--dev-bind-try` entries after the existing `--dev /dev` line. macOS is a no-op. `detectCudaAvailable()` is exported as a Linux-only stat-based helper for library consumers.

**Tech Stack:** TypeScript (ESM, NodeNext-style `.js` imports on `.ts` source), Zod for validation, Bun for tests (`bun:test`), bubblewrap for the actual sandbox.

**Spec:** `docs/superpowers/specs/2026-05-19-cuda-passthrough-design.md`

---

## File Structure

**Modify:**
- `src/sandbox/sandbox-config.ts` — add `HardwareConfigSchema`, `HardwareConfig` type, integration into `SandboxRuntimeConfigSchema`.
- `src/sandbox/linux-sandbox-utils.ts` — add `discoverCudaDevices()`, `detectCudaAvailable()`, two new fields on `LinuxSandboxParams`, CUDA bind emission inside `wrapCommandWithSandboxLinux`.
- `src/sandbox/sandbox-manager.ts` — call `discoverCudaDevices()` during initialize on Linux, cache result, thread `cudaEnabled` + `cudaDevices` into `wrapCommandWithSandboxLinux` params.
- `src/index.ts` — re-export `HardwareConfig` type and `detectCudaAvailable` function.
- `README.md` — new "GPU access (Linux)" subsection.
- `CLAUDE.md` — one-line architecture note under Linux back-end.
- `test/config-validation.test.ts` — extend with hardware-block cases.

**Create:**
- `test/sandbox/cuda-passthrough.test.ts` — arg-shape unit tests.
- `test/sandbox/cuda-smoke.test.ts` — GPU-host-gated smoke test scaffold.

---

## Task 1: Add `HardwareConfigSchema` to Zod schema

**Files:**
- Test: `test/config-validation.test.ts`
- Modify: `src/sandbox/sandbox-config.ts:354` (insertion before closing `})` of `SandboxRuntimeConfigSchema`; also add export at end of file)

- [ ] **Step 1: Write failing tests**

Append these tests at the end of the existing `describe('Config Validation', () => { ... })` block in `test/config-validation.test.ts`:

```ts
  describe('hardware block', () => {
    const baseConfig = {
      network: { allowedDomains: [], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
    }

    test('accepts missing hardware block', () => {
      const result = SandboxRuntimeConfigSchema.safeParse(baseConfig)
      expect(result.success).toBe(true)
    })

    test('accepts hardware.cuda = true', () => {
      const result = SandboxRuntimeConfigSchema.safeParse({
        ...baseConfig,
        hardware: { cuda: true },
      })
      expect(result.success).toBe(true)
      if (result.success) {
        expect(result.data.hardware?.cuda).toBe(true)
      }
    })

    test('accepts hardware.cuda = false', () => {
      const result = SandboxRuntimeConfigSchema.safeParse({
        ...baseConfig,
        hardware: { cuda: false },
      })
      expect(result.success).toBe(true)
    })

    test('accepts empty hardware block (cuda defaults to undefined)', () => {
      const result = SandboxRuntimeConfigSchema.safeParse({
        ...baseConfig,
        hardware: {},
      })
      expect(result.success).toBe(true)
    })

    test('rejects non-boolean hardware.cuda', () => {
      const result = SandboxRuntimeConfigSchema.safeParse({
        ...baseConfig,
        hardware: { cuda: 'yes' },
      })
      expect(result.success).toBe(false)
    })
  })
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `bun test test/config-validation.test.ts -t "hardware block"`
Expected: 5 tests fail. The "rejects non-boolean" test will pass (extra fields are stripped by default in Zod's `.object()`, and `cuda: 'yes'` ends up undefined which is fine — actually that test should fail at this stage because the field is silently dropped; that's the bug we want to catch with the strict schema). Most will fail with the success assertion (e.g. "expected `.data.hardware?.cuda` to be true, but `hardware` is undefined").

Actually, `z.object` strips unknown keys by default but does NOT reject unknown keys. So `hardware: { cuda: true }` parses successfully as `data.hardware === undefined`. The `accepts hardware.cuda = true` assertion `expect(result.data.hardware?.cuda).toBe(true)` will fail. Good — that's the failing test we need.

- [ ] **Step 3: Add the schema**

Edit `src/sandbox/sandbox-config.ts`. Insert this new schema after `SeccompConfigSchema` (around line 296, before `SandboxRuntimeConfigSchema`):

```ts
/**
 * Hardware passthrough configuration.
 *
 * v1 supports NVIDIA CUDA compute devices on Linux only. The flag is silently
 * ignored on macOS (matches the precedent of allowUnixSockets being Linux-
 * ignored). Missing block is equivalent to `{ cuda: false }`.
 */
export const HardwareConfigSchema = z.object({
  cuda: z
    .boolean()
    .optional()
    .describe(
      'Linux only: when true, bind compute-only NVIDIA device nodes ' +
        '(/dev/nvidiactl, /dev/nvidia-uvm, /dev/nvidia-uvm-tools, ' +
        '/dev/nvidia-caps, /dev/nvidia<N>) into the bwrap sandbox via ' +
        '--dev-bind-try. Display-oriented nodes (/dev/nvidia-modeset, ' +
        '/dev/dri) are intentionally excluded. macOS ignores this flag.',
    ),
})
```

Then add the field to `SandboxRuntimeConfigSchema` (line ~354, before the closing `})`):

```ts
  hardware: HardwareConfigSchema.optional().describe(
    'Optional hardware passthrough configuration (currently NVIDIA CUDA on Linux).',
  ),
```

And add a type export at the bottom of the file (after the existing `export type` block, around line 367):

```ts
export type HardwareConfig = z.infer<typeof HardwareConfigSchema>
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `bun test test/config-validation.test.ts -t "hardware block"`
Expected: 5 tests PASS.

Also run the full validation suite to confirm no regressions:

Run: `bun test test/config-validation.test.ts`
Expected: all tests PASS.

- [ ] **Step 5: Typecheck and commit**

Run: `npm run typecheck`
Expected: no errors.

```bash
git add src/sandbox/sandbox-config.ts test/config-validation.test.ts
git commit -m "feat(config): add hardware.cuda schema field

Adds optional hardware block to SandboxRuntimeConfig. Field is platform-
portable; Linux back-end will consume it, macOS path ignores it."
```

---

## Task 2: Export `HardwareConfig` type from library entry point

**Files:**
- Modify: `src/index.ts:7-12` (extend the existing `export type` block from `sandbox-config.js`)

- [ ] **Step 1: Add the export**

Edit `src/index.ts`. The existing block is:

```ts
export type {
  SandboxRuntimeConfig,
  NetworkConfig,
  FilesystemConfig,
  IgnoreViolationsConfig,
} from './sandbox/sandbox-config.js'
```

Change it to:

```ts
export type {
  SandboxRuntimeConfig,
  NetworkConfig,
  FilesystemConfig,
  IgnoreViolationsConfig,
  HardwareConfig,
} from './sandbox/sandbox-config.js'
```

Also extend the schema re-export block (currently exporting `*Schema` constants) to include `HardwareConfigSchema`:

```ts
export {
  SandboxRuntimeConfigSchema,
  NetworkConfigSchema,
  FilesystemConfigSchema,
  IgnoreViolationsConfigSchema,
  RipgrepConfigSchema,
  HardwareConfigSchema,
} from './sandbox/sandbox-config.js'
```

- [ ] **Step 2: Run typecheck**

Run: `npm run typecheck`
Expected: no errors. If `HardwareConfigSchema` isn't exported from `sandbox-config.ts`, the import will fail — go back to Task 1 and ensure `export` is on the schema constant.

- [ ] **Step 3: Run build to confirm declaration files emit cleanly**

Run: `npm run build`
Expected: build succeeds, `dist/index.d.ts` mentions `HardwareConfig` and `HardwareConfigSchema`.

Run: `grep -q HardwareConfig dist/index.d.ts && echo OK || echo MISSING`
Expected: `OK`.

- [ ] **Step 4: Commit**

```bash
git add src/index.ts
git commit -m "feat(api): export HardwareConfig type + schema from library entry"
```

---

## Task 3: Add `detectCudaAvailable()` + `discoverCudaDevices()` to linux-sandbox-utils

**Files:**
- Test: `test/sandbox/cuda-passthrough.test.ts` (new)
- Modify: `src/sandbox/linux-sandbox-utils.ts` (new exports, no existing logic changes yet)

- [ ] **Step 1: Create failing test file**

Create `test/sandbox/cuda-passthrough.test.ts` with:

```ts
import { describe, test, expect } from 'bun:test'
import { existsSync } from 'node:fs'
import { isLinux, isMacOS } from '../helpers/platform.js'
import {
  detectCudaAvailable,
  discoverCudaDevices,
} from '../../src/sandbox/linux-sandbox-utils.js'

describe('detectCudaAvailable', () => {
  test('returns false on macOS regardless of state', () => {
    if (!isMacOS) return
    expect(detectCudaAvailable()).toBe(false)
  })

  test('returns existence of /dev/nvidiactl on Linux', () => {
    if (!isLinux) return
    expect(detectCudaAvailable()).toBe(existsSync('/dev/nvidiactl'))
  })
})

describe('discoverCudaDevices', () => {
  test('always includes the four fixed compute nodes', () => {
    const devices = discoverCudaDevices()
    expect(devices).toContain('/dev/nvidiactl')
    expect(devices).toContain('/dev/nvidia-uvm')
    expect(devices).toContain('/dev/nvidia-uvm-tools')
    expect(devices).toContain('/dev/nvidia-caps')
  })

  test('does not include display nodes', () => {
    const devices = discoverCudaDevices()
    expect(devices).not.toContain('/dev/nvidia-modeset')
    expect(devices.some(d => d.startsWith('/dev/dri'))).toBe(false)
  })

  test('indexed nodes sorted and match /dev/nvidia<N> pattern', () => {
    const devices = discoverCudaDevices()
    const indexed = devices.filter(d => /^\/dev\/nvidia\d+$/.test(d))
    const sorted = [...indexed].sort()
    expect(indexed).toEqual(sorted)
  })
})
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `bun test test/sandbox/cuda-passthrough.test.ts`
Expected: All tests fail with "detectCudaAvailable is not a function" / "discoverCudaDevices is not a function" or an import-resolution error.

- [ ] **Step 3: Implement `discoverCudaDevices` + `detectCudaAvailable`**

Edit `src/sandbox/linux-sandbox-utils.ts`. At the top of the file (after the existing imports), confirm `fs` and the platform helper are imported. The file already imports `fs`. Add a `getPlatform` import if not already present — check by running `grep -n "from '../utils/platform" src/sandbox/linux-sandbox-utils.ts`. If missing, add:

```ts
import { getPlatform } from '../utils/platform.js'
```

Then add the following near the top of the file (after the other module-level helpers, e.g. after `DEFAULT_MANDATORY_DENY_SEARCH_DEPTH`):

```ts
// ============================================================================
// CUDA device passthrough
// ============================================================================

/**
 * NVIDIA compute device nodes that are always bound (via --dev-bind-try)
 * when hardware.cuda is enabled. Display-oriented nodes are intentionally
 * excluded — see spec docs/superpowers/specs/2026-05-19-cuda-passthrough-design.md.
 */
const CUDA_FIXED_NODES: readonly string[] = [
  '/dev/nvidiactl',
  '/dev/nvidia-uvm',
  '/dev/nvidia-uvm-tools',
  '/dev/nvidia-caps',
] as const

/**
 * Returns the list of NVIDIA device nodes to bind into the sandbox when
 * hardware.cuda is enabled. Combines the fixed compute-control nodes with
 * any discovered /dev/nvidia<N> device entries. Discovery never throws —
 * EACCES or other readdir failures on locked-down hosts are treated as an
 * empty indexed list, and the fixed nodes are still emitted (the caller
 * uses --dev-bind-try so missing nodes are non-fatal).
 */
export function discoverCudaDevices(): string[] {
  let indexed: string[] = []
  try {
    indexed = fs
      .readdirSync('/dev')
      .filter(n => /^nvidia\d+$/.test(n))
      .sort()
      .map(n => '/dev/' + n)
  } catch {
    // intentionally swallowed; see docstring
  }
  return [...CUDA_FIXED_NODES, ...indexed]
}

/**
 * Cheap probe library consumers can call to decide whether to set
 * `hardware.cuda = true`. Returns true only on Linux and only when
 * /dev/nvidiactl exists. Does not dlopen libcuda.
 */
export function detectCudaAvailable(): boolean {
  if (getPlatform() !== 'linux') return false
  try {
    return fs.existsSync('/dev/nvidiactl')
  } catch {
    return false
  }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `bun test test/sandbox/cuda-passthrough.test.ts`
Expected: all 5 tests in this file PASS (on either platform).

- [ ] **Step 5: Typecheck**

Run: `npm run typecheck`
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add src/sandbox/linux-sandbox-utils.ts test/sandbox/cuda-passthrough.test.ts
git commit -m "feat(linux): add discoverCudaDevices + detectCudaAvailable helpers

Pure-function helpers with no side effects. Discovery is non-throwing.
detectCudaAvailable returns false on non-Linux. No wiring into the sandbox
yet — that comes in subsequent tasks."
```

---

## Task 4: Export `detectCudaAvailable` from the library entry point

**Files:**
- Modify: `src/index.ts`

- [ ] **Step 1: Add the export**

Edit `src/index.ts`. Add a new export line after the existing utility-function exports section (after `export { getDefaultWritePaths } from './sandbox/sandbox-utils.js'`):

```ts
// CUDA passthrough helpers
export {
  detectCudaAvailable,
  discoverCudaDevices,
} from './sandbox/linux-sandbox-utils.js'
```

- [ ] **Step 2: Verify the import path resolves**

Run: `npm run typecheck`
Expected: no errors.

Run: `npm run build && grep -q detectCudaAvailable dist/index.js && echo OK || echo MISSING`
Expected: `OK`.

- [ ] **Step 3: Commit**

```bash
git add src/index.ts
git commit -m "feat(api): export detectCudaAvailable and discoverCudaDevices"
```

---

## Task 5: Thread `cudaEnabled` + `cudaDevices` through `LinuxSandboxParams`

**Files:**
- Modify: `src/sandbox/linux-sandbox-utils.ts:35-62` (extend `LinuxSandboxParams`)
- Modify: `src/sandbox/linux-sandbox-utils.ts:1066-1090` (extend destructuring in `wrapCommandWithSandboxLinux`)

This task only adds the parameter plumbing. The actual emission logic comes in Task 7. We split this off so each commit is small and the wiring is reviewable separately.

- [ ] **Step 1: Add fields to the interface**

Edit `LinuxSandboxParams` (line 35–62 in `src/sandbox/linux-sandbox-utils.ts`). Add at the end of the interface, before the closing `}`:

```ts
  /** Linux only: when true, bind NVIDIA compute device nodes into the sandbox. */
  cudaEnabled?: boolean
  /**
   * Linux only: the device-node paths to attempt --dev-bind-try for when
   * cudaEnabled is true. Caller computes this once at initialize() via
   * discoverCudaDevices() to avoid per-wrap filesystem scans. Defaulted to
   * an empty array if unset.
   */
  cudaDevices?: string[]
```

- [ ] **Step 2: Destructure them in `wrapCommandWithSandboxLinux`**

Inside the destructuring block at line 1069–1089, add:

```ts
    cudaEnabled = false,
    cudaDevices = [],
```

Position alphabetically near the other booleans (e.g. between `allowGitConfig` and `seccompConfig` is fine — exact order does not matter for runtime behavior, but keep it tidy).

- [ ] **Step 3: Typecheck**

Run: `npm run typecheck`
Expected: no errors. `cudaEnabled` is destructured but not yet referenced — TS may warn about `noUnusedLocals`. Confirm whether the existing destructure suppresses that (other unused locals are present in the file). If TS errors with "is declared but never used":
  - Suppress temporarily by referencing them in a no-op `void` comment line:
    ```ts
    void cudaEnabled
    void cudaDevices
    ```
  - These get removed in Task 7 when real usage lands.

- [ ] **Step 4: Run the existing test suite to confirm no regressions**

Run: `bun test test/sandbox/wrap-with-sandbox.test.ts`
Expected: existing tests still PASS.

- [ ] **Step 5: Commit**

```bash
git add src/sandbox/linux-sandbox-utils.ts
git commit -m "refactor(linux): plumb cudaEnabled/cudaDevices through LinuxSandboxParams

No behavior change yet — fields are destructured but unused. Emission logic
lands in the next commit."
```

---

## Task 6: Discover devices in `SandboxManager.initialize` and forward to wrap call

**Files:**
- Modify: `src/sandbox/sandbox-manager.ts` (around line 716, the Linux wrap call site)
- Modify: `src/sandbox/sandbox-manager.ts` (initialize block — find via `grep -n "async function initialize\|export.*initialize"`)

- [ ] **Step 1: Locate the initialize function**

Run: `grep -n "function initialize\b\|async function initialize\b" src/sandbox/sandbox-manager.ts`
Expected: prints the line where `initialize(...)` is defined. Read 30 lines from that location to understand its current body.

- [ ] **Step 2: Add module-level cache**

Near the top of `src/sandbox/sandbox-manager.ts`, in the "Private Module State" section (around line 56–66), add:

```ts
let cudaDevicesCache: string[] = []
```

Also add an import at the top of the file (extend the existing `linux-sandbox-utils` import):

```ts
import {
  wrapCommandWithSandboxLinux,
  initializeLinuxNetworkBridge,
  type LinuxNetworkBridgeContext,
  checkLinuxDependencies,
  type SandboxDependencyCheck,
  cleanupBwrapMountPoints,
  discoverCudaDevices,
} from './linux-sandbox-utils.js'
```

- [ ] **Step 3: Populate the cache during initialize (Linux only)**

Inside the `initialize` function body, after platform detection and before any other Linux-specific setup, add:

```ts
if (getPlatform() === 'linux') {
  cudaDevicesCache = discoverCudaDevices()
}
```

`getPlatform` is already imported (see line 7 of sandbox-manager.ts). If it isn't in scope at the chosen insertion point, hoist the call to the start of the function.

- [ ] **Step 4: Reset the cache in `reset`**

Locate `async function reset` (`grep -n "function reset" src/sandbox/sandbox-manager.ts`). Add `cudaDevicesCache = []` alongside the other state resets so re-initialize after reset reruns discovery.

- [ ] **Step 5: Forward to the Linux wrap call**

In the existing `case 'linux':` block (line 715–745), extend the params object passed to `wrapCommandWithSandboxLinux`:

```ts
        cudaEnabled: config?.hardware?.cuda === true,
        cudaDevices: cudaDevicesCache,
```

Place these new keys adjacent to the other Linux-only fields (e.g. after `socatPath: config?.socatPath,`).

- [ ] **Step 6: Typecheck**

Run: `npm run typecheck`
Expected: no errors. If `config?.hardware?.cuda` fails type lookup, double-check Task 1 added the field.

- [ ] **Step 7: Run existing tests to confirm no regressions**

Run: `bun test test/sandbox/wrap-with-sandbox.test.ts test/cli-config-loading.test.ts`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add src/sandbox/sandbox-manager.ts
git commit -m "feat(manager): cache CUDA device list at init and pass into Linux wrap

Discovery runs once per process on Linux; reset clears the cache so a
re-initialize re-probes. macOS path unchanged."
```

---

## Task 7: Emit `--dev-bind-try` entries inside `wrapCommandWithSandboxLinux`

**Files:**
- Test: `test/sandbox/cuda-passthrough.test.ts` (extend)
- Modify: `src/sandbox/linux-sandbox-utils.ts:1221` (the `--dev /dev` line — emission lands directly after it)

- [ ] **Step 1: Extend the test file with arg-shape tests**

In `test/sandbox/cuda-passthrough.test.ts`, append a new `describe` block. Replace the existing file body's final closing line (after the `discoverCudaDevices` describe) by adding:

```ts
import { wrapCommandWithSandboxLinux } from '../../src/sandbox/linux-sandbox-utils.js'

describe.if(isLinux)('wrapCommandWithSandboxLinux CUDA arg emission', () => {
  // Minimal config that triggers wrapping (we need at least one restriction
  // so wrap doesn't short-circuit and return the bare command).
  const baseParams = {
    command: 'echo hi',
    needsNetworkRestriction: true as const,
    writeConfig: { allowOnly: ['/tmp'], denyWithinAllow: [] },
    // allowAllUnixSockets skips the seccomp wrapper so assertions over the
    // wrapped command string are less brittle.
    allowAllUnixSockets: true,
  }

  test('cudaEnabled=false (default) emits no nvidia bind entries', async () => {
    const wrapped = await wrapCommandWithSandboxLinux({ ...baseParams })
    expect(wrapped).not.toContain('nvidia')
  })

  test('cudaEnabled=true emits --dev-bind-try for each device', async () => {
    const wrapped = await wrapCommandWithSandboxLinux({
      ...baseParams,
      cudaEnabled: true,
      cudaDevices: [
        '/dev/nvidiactl',
        '/dev/nvidia-uvm',
        '/dev/nvidia-uvm-tools',
        '/dev/nvidia-caps',
        '/dev/nvidia0',
      ],
    })
    expect(wrapped).toContain('--dev-bind-try /dev/nvidiactl /dev/nvidiactl')
    expect(wrapped).toContain('--dev-bind-try /dev/nvidia-uvm /dev/nvidia-uvm')
    expect(wrapped).toContain(
      '--dev-bind-try /dev/nvidia-uvm-tools /dev/nvidia-uvm-tools',
    )
    expect(wrapped).toContain(
      '--dev-bind-try /dev/nvidia-caps /dev/nvidia-caps',
    )
    expect(wrapped).toContain('--dev-bind-try /dev/nvidia0 /dev/nvidia0')
  })

  test('cudaEnabled=true with empty device list emits no bind entries', async () => {
    const wrapped = await wrapCommandWithSandboxLinux({
      ...baseParams,
      cudaEnabled: true,
      cudaDevices: [],
    })
    expect(wrapped).not.toContain('--dev-bind-try')
  })

  test('cudaEnabled=true never emits display nodes', async () => {
    const wrapped = await wrapCommandWithSandboxLinux({
      ...baseParams,
      cudaEnabled: true,
      // Caller passes a list that contains a display node — the wrap function
      // should still emit it (it trusts the caller). The exclusion guarantee
      // lives in discoverCudaDevices, not the wrap call. Verify discovery's
      // own output has no modeset/dri (already covered above) and that
      // production code path uses the discovery function — that's the
      // integration boundary.
      cudaDevices: ['/dev/nvidiactl'],
    })
    expect(wrapped).not.toContain('nvidia-modeset')
    expect(wrapped).not.toContain('/dev/dri')
  })

  test('cudaEnabled=false ignores cudaDevices entirely', async () => {
    const wrapped = await wrapCommandWithSandboxLinux({
      ...baseParams,
      cudaEnabled: false,
      cudaDevices: ['/dev/nvidiactl', '/dev/nvidia0'],
    })
    expect(wrapped).not.toContain('nvidia')
    expect(wrapped).not.toContain('--dev-bind-try')
  })
})
```

Note on `baseParams`: confirm `writeConfig`'s shape matches `FsWriteRestrictionConfig` (`grep -n "allowOnly" src/sandbox/sandbox-schemas.ts` to verify). If the field name differs, adjust `baseParams.writeConfig` accordingly. If a minimal valid `writeConfig` requires more fields, add them — the goal is just to make `wrapCommandWithSandboxLinux` proceed past its early-return guard at line 1098–1104.

- [ ] **Step 2: Run tests to verify they fail**

Run: `bun test test/sandbox/cuda-passthrough.test.ts -t "CUDA arg emission"`
Expected: all 5 emission tests FAIL — the wrap function ignores `cudaEnabled`/`cudaDevices`, so the assertions that look for `--dev-bind-try` will fail, and the `cudaEnabled=false` regression tests should already pass (no nvidia is currently emitted). Expect at least the two positive-emission tests to FAIL.

- [ ] **Step 3: Implement emission**

Edit `src/sandbox/linux-sandbox-utils.ts`. Find line 1221:

```ts
    // Always bind /dev
    bwrapArgs.push('--dev', '/dev')
```

Immediately after that line, insert:

```ts
    // ========== CUDA DEVICE PASSTHROUGH (NVIDIA, compute-only) ==========
    // Display-oriented nodes (/dev/nvidia-modeset, /dev/dri/*) are
    // intentionally excluded. The caller (SandboxManager) computes the
    // device list via discoverCudaDevices() at initialize() time. We use
    // --dev-bind-try so a missing node (stale cache, partial host, node
    // disappeared between discovery and exec) is non-fatal.
    if (cudaEnabled && cudaDevices.length > 0) {
      for (const devicePath of cudaDevices) {
        bwrapArgs.push('--dev-bind-try', devicePath, devicePath)
      }
    }
```

Also remove the `void cudaEnabled` / `void cudaDevices` no-op lines added in Task 5 (if any).

- [ ] **Step 4: Run tests to verify they pass**

Run: `bun test test/sandbox/cuda-passthrough.test.ts`
Expected: all tests in the file PASS.

- [ ] **Step 5: Run the broader sandbox test suite to confirm no regressions**

Run: `bun test test/sandbox/wrap-with-sandbox.test.ts test/sandbox/integration.test.ts`
Expected: PASS (smoke for the file; full integration may need a Linux host with bwrap installed — skip locally and rely on CI if on macOS).

- [ ] **Step 6: Typecheck**

Run: `npm run typecheck`
Expected: no errors.

- [ ] **Step 7: Commit**

```bash
git add src/sandbox/linux-sandbox-utils.ts test/sandbox/cuda-passthrough.test.ts
git commit -m "feat(linux): emit --dev-bind-try for NVIDIA compute nodes when cuda enabled

Compute-only device passthrough. Display nodes excluded by the caller's
discoverCudaDevices function. Missing nodes are non-fatal via --dev-bind-try."
```

---

## Task 8: macOS no-op assertion

**Files:**
- Test: `test/sandbox/cuda-passthrough.test.ts` (extend)

- [ ] **Step 1: Add a macOS-gated assertion**

Note: `wrapCommandWithSandboxMacOS` is synchronous (returns `string`, not `Promise<string>`). The `MacOSSandboxParams` interface (in `src/sandbox/macos-sandbox-utils.ts:23`) requires `readConfig` and `writeConfig` (both can be `undefined`) and `command` + `needsNetworkRestriction`. All other fields are optional.

Append to `test/sandbox/cuda-passthrough.test.ts`:

```ts
import { wrapCommandWithSandboxMacOS } from '../../src/sandbox/macos-sandbox-utils.js'
import { tmpdir } from 'node:os'

describe.if(isMacOS)('macOS ignores hardware.cuda', () => {
  test('Seatbelt profile contains no nvidia/cuda references', () => {
    // The macOS code path never reads `config.hardware`. This test is a
    // regression guard: it locks in that no future change accidentally
    // pipes CUDA logic into the macOS profile generator.
    const wrapped = wrapCommandWithSandboxMacOS({
      command: 'echo hi',
      needsNetworkRestriction: true,
      readConfig: { denyOnly: [] },
      writeConfig: { allowOnly: [tmpdir()], denyWithinAllow: [] },
    })

    expect(wrapped.toLowerCase()).not.toContain('nvidia')
    expect(wrapped.toLowerCase()).not.toContain('cuda')
  })
})
```

- [ ] **Step 2: Run on macOS (or skip on Linux)**

On macOS: `bun test test/sandbox/cuda-passthrough.test.ts -t "macOS ignores"`
Expected: 1 test PASS.

On Linux: the `describe.if(isMacOS)` block is skipped — test runner reports it as skipped, not failed.

- [ ] **Step 3: Commit**

```bash
git add test/sandbox/cuda-passthrough.test.ts
git commit -m "test(macos): assert hardware.cuda is silently ignored in Seatbelt output"
```

---

## Task 9: GPU-host smoke test scaffold

**Files:**
- Create: `test/sandbox/cuda-smoke.test.ts`

- [ ] **Step 1: Create the smoke test scaffold**

Create `test/sandbox/cuda-smoke.test.ts` with:

```ts
import { describe, test, expect } from 'bun:test'
import { existsSync } from 'node:fs'
import { isLinux } from '../helpers/platform.js'
import { spawnAsync } from '../helpers/spawn.js'
import { SandboxManager } from '../../src/sandbox/sandbox-manager.js'

/**
 * GPU-host smoke test for CUDA passthrough. Skips cleanly when:
 *   - not running on Linux
 *   - /dev/nvidiactl is absent (no NVIDIA driver on host)
 *   - nvidia-smi is not installed (CI runners typically lack it)
 *
 * If this test fails specifically because NVIDIA proc metadata is missing
 * (e.g. CUDA init error code 802 / "system not yet initialized"), file a
 * follow-up amendment proposing a read-only /proc/driver/nvidia bind in the
 * Linux back-end, backed by the failure evidence.
 */
const gpuAvailable = isLinux && existsSync('/dev/nvidiactl')

describe.if(gpuAvailable)('CUDA passthrough smoke (GPU host)', () => {
  test('nvidia-smi -L runs under sandbox and lists GPUs', async () => {
    await SandboxManager.initialize({
      network: { allowedDomains: [], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: ['/tmp'], denyWrite: [] },
      hardware: { cuda: true },
    })

    try {
      const wrapped = await SandboxManager.wrapWithSandbox('nvidia-smi -L')
      const result = await spawnAsync(wrapped, { timeout: 15_000 })

      // If nvidia-smi is missing entirely the wrapped command exits 127 — skip
      // soft rather than fail (smoke test gating is best-effort).
      if (result.status === 127) {
        console.warn('nvidia-smi not installed — skipping smoke assertion')
        return
      }

      expect(result.status).toBe(0)
      expect(result.stdout).toMatch(/GPU/)

      // Detect the procfs-metadata failure mode and surface a hint:
      if (
        result.stderr.includes('CUDA_ERROR_NO_DEVICE') ||
        result.stderr.includes('system not yet initialized') ||
        result.stderr.includes('/proc/driver/nvidia')
      ) {
        throw new Error(
          'CUDA init failed in a way that suggests /proc/driver/nvidia ' +
            'is needed inside the sandbox. File a follow-up amendment ' +
            'with this stderr attached:\n' +
            result.stderr,
        )
      }
    } finally {
      await SandboxManager.reset()
    }
  })
})
```

- [ ] **Step 2: Run on a GPU host (if available) or confirm clean skip elsewhere**

Run: `bun test test/sandbox/cuda-smoke.test.ts`
Expected:
- On a Linux GPU host with nvidia-smi installed: 1 test PASS, asserting `GPU` is in `nvidia-smi -L` output.
- On a Linux GPU host without nvidia-smi: 1 test runs, logs the warning, returns without an assertion (no failure).
- On Linux without `/dev/nvidiactl` or on macOS: 0 tests run (describe-block skipped).

- [ ] **Step 3: Run the full test suite to confirm clean skip in CI-like environment**

Run: `npm test`
Expected: all tests PASS or are skipped. No new failures.

- [ ] **Step 4: Commit**

```bash
git add test/sandbox/cuda-smoke.test.ts
git commit -m "test(linux): add GPU-host smoke scaffold for CUDA passthrough

Skips cleanly without /dev/nvidiactl or nvidia-smi. Surfaces /proc/driver/nvidia
hint when CUDA init fails in a way that points at missing procfs metadata."
```

---

## Task 10: Documentation

**Files:**
- Modify: `README.md` (insert new subsection in the Configuration section)
- Modify: `CLAUDE.md` (one-line architecture note)

- [ ] **Step 1: Add README subsection**

In `README.md`, find the "#### Other Configuration" subsection (where `ignoreViolations`, `enableWeakerNestedSandbox`, etc. are documented — around the line `- \`ignoreViolations\` - Object mapping command patterns`). Insert a new subsection immediately before it:

```markdown
#### Hardware Passthrough (Linux only)

Opt-in NVIDIA CUDA compute device passthrough. Off by default. macOS ignores the
flag.

```json
{
  "hardware": { "cuda": true }
}
```

When `hardware.cuda` is `true` on Linux, the following compute-only NVIDIA
device nodes are bound into the sandbox via `--dev-bind-try`:

- `/dev/nvidiactl`
- `/dev/nvidia-uvm`
- `/dev/nvidia-uvm-tools`
- `/dev/nvidia-caps`
- `/dev/nvidia<N>` (each compute device discovered at sandbox initialization)

Display-oriented nodes are intentionally excluded: `/dev/nvidia-modeset`,
`/dev/dri/*`. Missing nodes are non-fatal — `--dev-bind-try` skips them, and
CUDA programs fail at their normal runtime path if devices are unavailable.

Library consumers can probe for CUDA support before enabling the flag:

```typescript
import { detectCudaAvailable } from '@anthropic-ai/sandbox-runtime'

const config = {
  // ...
  hardware: { cuda: detectCudaAvailable() },
}
```

**Security note:** CUDA driver passthrough exposes the host's NVIDIA kernel
driver to the sandboxed workload. Only enable this when the workload actually
needs GPU compute access. The seccomp filter does not block NVIDIA ioctls.
```

(Note: the JSON code fence inside the markdown above is intentional — replicate exactly. Be careful with the nested triple-backticks when editing.)

- [ ] **Step 2: Add `CLAUDE.md` mention**

In `CLAUDE.md`, find the bullet under "Platform back-ends" that describes `linux-sandbox-utils.ts`. Append one sentence at the end of that bullet:

> Optional NVIDIA CUDA compute-device passthrough is gated by `hardware.cuda` in the config (off by default; macOS ignores it).

- [ ] **Step 3: Spot-check rendering**

Run: `grep -n "Hardware Passthrough" README.md`
Expected: one hit, in the Configuration section.

Run: `grep -n "hardware.cuda" CLAUDE.md`
Expected: one hit.

- [ ] **Step 4: Commit**

```bash
git add README.md CLAUDE.md
git commit -m "docs: document hardware.cuda passthrough and detectCudaAvailable helper"
```

---

## Final verification

- [ ] **Step 1: Run the full test suite**

Run: `npm test`
Expected: all tests PASS (or skip cleanly on hosts without GPU/Linux).

- [ ] **Step 2: Run typecheck + lint**

Run: `npm run typecheck && npm run lint:check`
Expected: zero errors and zero lint warnings on changed files.

- [ ] **Step 3: Build and confirm artifact**

Run: `npm run build`
Expected: build succeeds.

Run: `grep -E "HardwareConfig|detectCudaAvailable|discoverCudaDevices" dist/index.d.ts`
Expected: all three identifiers appear.

- [ ] **Step 4: Confirm the branch is ready**

Run: `git log --oneline gpu_support ^main`
Expected: roughly 10 commits, one per task above, in order.

- [ ] **Step 5: Push (only if user instructs)**

Do not push or open a PR without explicit user confirmation. The branch is `gpu_support`.

---

## Self-review notes

- **Spec coverage:** every section of `2026-05-19-cuda-passthrough-design.md` maps to one or more tasks above:
  - Schema (spec §Configuration) → Task 1, validated in `test/config-validation.test.ts`.
  - API surface re-exports (spec §API Surface) → Tasks 2 & 4.
  - Device discovery + caching at init (spec §Runtime Model) → Tasks 3 & 6.
  - Bwrap arg emission (spec §Bubblewrap Behavior) → Tasks 5 & 7.
  - Error handling (spec §Error Handling) → covered implicitly by `--dev-bind-try`, the swallowed `readdir` error in `discoverCudaDevices`, and macOS no-op test (Task 8).
  - Tests (spec §Testing) → Tasks 1, 3, 7, 8, 9.
  - Documentation (spec §Documentation) → Task 10.
  - Implementation boundaries (spec §Implementation Boundaries) → Files matched exactly in the File Structure section above.
- **Naming consistency:** `discoverCudaDevices`, `detectCudaAvailable`, `cudaEnabled`, `cudaDevices`, `cudaDevicesCache`, `CUDA_FIXED_NODES`, `hardware.cuda` — all consistent across tasks. `HardwareConfig` and `HardwareConfigSchema` consistent across schema, exports, and docs.
- **No placeholders:** every step has either exact code or an exact command + expected output.
- **Out-of-scope reminders:** `/proc/driver/nvidia`, `/dev/dri`, non-NVIDIA GPUs, render nodes, and macOS GPU access remain deferred. The smoke test surfaces evidence that would justify revisiting `/proc/driver/nvidia` in a follow-up amendment.
