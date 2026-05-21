# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

`@anthropic-ai/sandbox-runtime` (CLI: `srt`). TypeScript library + CLI that wraps arbitrary processes in OS-level sandboxes for filesystem and network restrictions. Used by Claude Code and shipped as an open-source research preview. Published to npm; consumed both as a library (`SandboxManager`) and a binary.

## Commands

Tests use **Bun's test runner** (`bun test`), not Jest/Vitest. The published artifact is built with `tsc`, but tests run TypeScript directly through Bun.

```bash
npm install                  # install deps
npm run build                # tsc → dist/
npm run build:seccomp        # build vendor/seccomp/{x64,arm64}/apply-seccomp (Linux only; needs gcc + libseccomp-dev)
npm test                     # bun test (runs everything in test/)
bun test test/sandbox/integration.test.ts          # single file
bun test --test-name-pattern "denies write"        # single test by name
npm run typecheck            # tsc --noEmit
npm run lint                 # eslint --fix (cached)
npm run lint:check           # eslint without fix
npm run format               # prettier
```

Husky runs `lint-staged` (eslint + prettier on `*.ts`) on pre-commit.

## Runtime requirements for tests

Integration tests actually spawn `bwrap` / `sandbox-exec` and real proxies — they are not mocked. To run them you need:

- **Linux**: `bubblewrap`, `socat`, `ripgrep`, plus `vendor/seccomp/{arch}/apply-seccomp` built via `npm run build:seccomp`. Many tests will silently skip or fail without these.
- **Linux user namespaces**: Ubuntu 24.04+ blocks `unshare(CLONE_NEWUSER)` from gaining capabilities. Run `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0` before testing locally (CI does this in `.github/workflows/integration-tests.yml`).
- **macOS**: `ripgrep` (via `brew install ripgrep`).

Tests use `test/helpers/platform.ts` (`isLinux`, etc.) to skip platform-specific suites — follow that pattern when adding new tests.

## Architecture

### Entry points

- `src/cli.ts` — `srt` binary. Parses argv via `commander`, loads `~/.srt-settings.json` (or `--settings`), calls `SandboxManager.initialize(config)`, shell-quotes argv (via `shell-quote`), then `SandboxManager.wrapWithSandbox(command)` and `spawn`s through `bash -c`. The `-c <command>` form passes the raw string with no escaping. `--control-fd <n>` reads newline-delimited JSON config updates from a file descriptor while the child runs (used by Claude Code for live re-permissioning).
- `src/index.ts` — library surface. Exports `SandboxManager`, `SandboxViolationStore`, all config types/schemas, and request-filter types.

### SandboxManager (singleton module state)

`src/sandbox/sandbox-manager.ts` is **module-global singleton state**, not a class. It holds the active `config`, the HTTP+SOCKS proxy servers, the macOS log monitor, the MITM CA, and the violation store. Key lifecycle:

1. `initialize(config)` — validates config (Zod), spins up `http-proxy.ts` + `socks-proxy.ts`, on Linux also `initializeLinuxNetworkBridge` (socat bridges over Unix sockets), starts macOS log monitor, lazily creates the MITM CA when TLS termination is requested.
2. `wrapWithSandbox(command)` — dispatches to `wrapCommandWithSandboxLinux` or `wrapCommandWithSandboxMacOS` to build the actual bwrap/sandbox-exec invocation string.
3. `updateConfig(newConfig)` — hot-reload path used by `--control-fd`. Must keep proxy ports stable across updates.
4. `cleanupAfterCommand()` / `reset()` — bwrap leaves empty mount-target files on the host for non-existent deny paths; cleanup removes them. Registered on `exit`/`SIGINT`/`SIGTERM`.

Because state is module-global, **tests must call `SandboxManager.reset()` between cases** or share a config via `beforeAll`/`afterAll`. Re-initializing without reset will leak proxies.

### Platform back-ends

- `linux-sandbox-utils.ts` (~47KB) — assembles the bwrap argv: bind mounts for allowed paths, `--ro-bind` for deny-but-readable, `--unshare-net` to strip the network namespace, env-var-based proxy injection (`HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY`). Mandatory-deny logic uses `ripgrep` to scan up to `mandatoryDenySearchDepth` (default 3) for sensitive files inside allowed write paths. Wraps the user command in `apply-seccomp` (see below) to add the AF_UNIX block + nested PID namespace. Optional NVIDIA CUDA compute-device passthrough is gated by `hardware.cuda` in the config (off by default; macOS ignores it).
- `macos-sandbox-utils.ts` (~30KB) — generates Seatbelt `.sb` profiles inline, invokes `sandbox-exec -p`. Supports git-style glob patterns natively (Linux does not — paths are literal). Also taps `OSLog` (`log stream`) for real-time violation events that flow into `SandboxViolationStore`.

### Seccomp layer (Linux only)

`vendor/seccomp-src/` contains two C programs:

- `seccomp-unix-block.c` — build-time tool that emits per-architecture BPF blobs.
- `apply-seccomp.c` — the runtime helper that gets exec'd inside bwrap. It creates a **nested user+PID+mount namespace**, remounts `/proc`, becomes PID 1 (`PR_SET_DUMPABLE=0`), applies the BPF filter via `prctl(PR_SET_SECCOMP)`, then execs the user command.

The BPF filter blocks `socket(AF_UNIX, ...)`, `io_uring_setup`, `io_uring_enter`, `io_uring_register`. The nested PID namespace is what makes the boundary tamper-resistant: the socat helpers and bwrap init are unreachable via `ptrace`/`/proc/N/mem` from inside.

Pre-built binaries for x64 + arm64 ship in `vendor/seccomp/{arch}/apply-seccomp` (built by `vendor/seccomp/build.ts`, run via `npm run build:seccomp`). Other arches must set `allowAllUnixSockets: true` or run without seccomp.

### Network filtering

- `http-proxy.ts` — HTTP/HTTPS proxy. Matches against `allowedDomains` / `deniedDomains` (deny wins). Wildcards `*.example.com` are supported but rejected for IP literals (see `matchesDomainPattern` for the IPv6 zone-id pitfall).
- `socks-proxy.ts` — SOCKS5 for non-HTTP TCP. Same allow/deny logic.
- `tls-terminate-proxy.ts` — optional MITM termination per domain (uses `mitm-ca.ts` for an ephemeral CA + `mitm-leaf.ts` for per-host leaves). Enables full request inspection via `filterRequest` callback.
- `parent-proxy.ts` — if the user has an upstream proxy (`HTTPS_PROXY` env / config), the sandbox chains to it.
- `request-filter.ts` — `FilterRequestCallback` type for per-request decisions returned to the proxies.

On Linux the proxies listen on Unix sockets that bwrap bind-mounts into the sandbox; the network namespace is fully stripped. On macOS the Seatbelt profile only allows TCP to specific localhost ports where the proxies listen.

### Configuration

`src/sandbox/sandbox-config.ts` is the **source of truth** for the public config schema (Zod). `SandboxRuntimeConfigSchema` runs at `initialize()` time and rejects malformed input. When extending the config:

1. Add the field + Zod validation in `sandbox-config.ts`.
2. Re-export the type from `src/index.ts`.
3. Wire it through `SandboxManager` and the platform back-end.
4. Update the README config reference + add a test in `test/config-validation.test.ts`.

Domain patterns reject overly broad wildcards (`*`, `*.com`) — see `domainPatternSchema`.

### Conventions

- **ESM only.** `"type": "module"` in package.json. All imports use `.js` extensions even for `.ts` source — TypeScript NodeNext-style. Don't drop the extension.
- **Debug logging** uses `SRT_DEBUG=true` (NOT `DEBUG=...`) to avoid clashing with the npm `debug` package. Use `logForDebugging()` from `utils/debug.ts`, never `console.log` in library code.
- **Don't `console.log` in library code.** Use `logForDebugging`. The CLI may write to stderr for user-facing errors only.
- TS is strict (`strict`, `noUnusedLocals`, `noUnusedParameters`, `noImplicitReturns`). The build will fail on unused vars — prefix with `_` to intentionally keep.
- ESLint config (`eslint.config.js`) blocks `console.log` and enforces import resolution; trust the lint output over local intuition.
- Prefer literal paths over relying on shell expansion. `~` is expanded by the config loader, not the shell.
