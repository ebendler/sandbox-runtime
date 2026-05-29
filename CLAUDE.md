# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Anthropic Sandbox Runtime (`srt`): a TypeScript library + CLI that wraps arbitrary processes in OS-level filesystem and network sandboxes without containers. Published as `@anthropic-ai/sandbox-runtime`. Uses `sandbox-exec`/Seatbelt on macOS, `bubblewrap` + seccomp BPF on Linux. Windows support is in progress via a separate Rust helper (`vendor/srt-win/`) not yet wired into the TS layer.

The runtime is Bun-first (tests run under `bun test`) but the published artifact must work under Node ≥ 22.

## Common commands

```bash
npm run build              # tsc → dist/
npm run typecheck          # tsc --noEmit
npm test                   # bun test (entire suite)
bun test test/sandbox/foo.test.ts            # single file
bun test --test-name-pattern "regex"         # filter by test name
npm run lint               # eslint --fix
npm run lint:check         # eslint, no fix (use for CI-equivalent check)
npm run format             # prettier --write
npm run build:seccomp      # Linux only — rebuilds vendor/seccomp/{x64,arm64}/apply-seccomp
```

CI builds seccomp binaries before running tests on Linux. If you're touching anything that calls into the seccomp layer, run `npm run build:seccomp` first.

A husky pre-commit hook runs lint-staged (eslint + prettier on staged `*.ts`).

## Architecture

### Entry points

- `src/cli.ts` — the `srt` binary. Loads config from `~/.srt-settings.json` (or `--settings`), initializes `SandboxManager`, then spawns `bash -c <wrapped-command>`. Supports `--control-fd` for live config updates (JSON-lines protocol).
- `src/index.ts` — library surface. The public API is `SandboxManager` (singleton w/ module-level state) plus zod schemas and types from `src/sandbox/sandbox-config.ts` and `src/sandbox/sandbox-schemas.ts`.

### SandboxManager lifecycle

`src/sandbox/sandbox-manager.ts` owns global state for the sandbox: the HTTP proxy, SOCKS5 proxy, MITM CA, and the Linux network-bridge context. The flow is:

1. `SandboxManager.initialize(config)` — validates config, starts proxies on the host, sets up `process.exit/SIGINT/SIGTERM` cleanup handlers, and on Linux brings up Unix-socket bridges (`socat`) that get bind-mounted into the sandbox.
2. `SandboxManager.wrapWithSandbox(command)` — produces a platform-specific wrapped command string. On macOS this is a `sandbox-exec` invocation with a dynamically generated Seatbelt profile; on Linux it's `bwrap … apply-seccomp … bash -c <command>`.
3. `SandboxManager.cleanupAfterCommand()` — removes bwrap bind-mount artifacts the kernel leaves behind on the host.
4. `SandboxManager.updateConfig(...)` — hot-swaps the in-memory config used by the proxy filters; the spawned child is unaffected (its OS-level rules are baked in at wrap time).

Platform branches live in `linux-sandbox-utils.ts` and `macos-sandbox-utils.ts`. Shared logic (path expansion, glob handling, mandatory deny paths, default write paths) lives in `sandbox-utils.ts`.

### Network isolation

Both proxies run on the host, in-process:

- `http-proxy.ts` — HTTP/HTTPS forward proxy with domain allowlisting; can transparently MITM if a CA is configured (`mitm-ca.ts`, `mitm-leaf.ts`, `tls-terminate-proxy.ts`).
- `socks-proxy.ts` — SOCKS5 for everything else.
- `parent-proxy.ts` — when there's an upstream corporate proxy, requests get tunneled through it. Also owns host canonicalization (`canonicalizeHost`, `isValidHost`, `stripBrackets`) — these are security-sensitive: matchers use string suffixes that can be bypassed by e.g. inet_aton shorthand or null bytes if you skip canonicalization.
- `request-filter.ts` — per-request callback hook for callers that want custom decisioning beyond domain allow/deny lists.

On Linux the sandboxed process has its network namespace removed; proxies are reached through Unix sockets bind-mounted in. On macOS the Seatbelt profile permits only the proxy's localhost ports.

### Filesystem isolation — read vs write semantics are intentionally asymmetric

This trips people up regularly. From `sandbox-schemas.ts`:

- **Read** is deny-then-allow. Empty `denyRead: []` means **everything is readable**. `allowRead` carves exceptions *back in* on top of `denyRead`. `allowRead` wins ties.
- **Write** is allow-only. Empty `allowWrite: []` means **nothing is writable**. `denyWrite` carves exceptions *back out* on top of `allowWrite`. `denyWrite` wins ties.

Similarly, empty `network.allowedDomains: []` means no network. Don't treat empty arrays as "no restrictions" — it depends on which list.

**Glob support is platform-split.** macOS uses git-style globs (`*`, `**`, `?`, `[abc]`) compiled into the Seatbelt profile. Linux uses bubblewrap bind mounts which can't glob — paths are literal. `sandbox-utils.ts:expandGlobPattern` and friends paper over this.

### Mandatory deny paths

Some paths are *always* read-only regardless of `allowWrite`: shell rc files, `.git/hooks/`, `.git/config`, `.vscode/`, `.idea/`, `.claude/commands/`, `.claude/agents/`, `.mcp.json`, etc. This is defense-in-depth against sandbox escape via config tampering. On Linux this can only protect files that already exist (bind-mount limitation); on macOS the glob covers nonexistent paths too. `mandatoryDenySearchDepth` controls how deep the ripgrep scan goes.

### Seccomp (Linux Unix-socket blocking)

`vendor/seccomp-src/` holds two C programs:

- `seccomp-unix-block.c` — builds, at build time, the BPF filter that returns EPERM for `socket(AF_UNIX, …)` and the io_uring socket-creation syscalls. Output is a `.bpf` blob.
- `apply-seccomp.c` — runtime helper. Forks a nested user+PID+mount namespace, becomes PID 1 inside it, loads the baked-in BPF, and execs the user's command. The PID-namespace nesting is load-bearing: it prevents the sandboxed process from ptracing the unfiltered bwrap/socat helpers.

`vendor/seccomp/build.ts` (bun script) compiles both for x64 and aarch64 and produces `vendor/seccomp/{x64,arm64}/apply-seccomp`. These static binaries ship in the published package — no runtime gcc/libseccomp needed on supported architectures.

If you change either C file, run `npm run build:seccomp` before running tests; CI does this automatically per arch.

### CDI device passthrough (Linux)

`config.cdi` opts the sandbox into CNCF [Container Device Interface](https://github.com/cncf-tags/container-device-interface) support. `SandboxManager.initialize()` walks `cdi.specDirs` (default `/etc/cdi`, `/var/run/cdi`) and builds a `Registry` via the `@cncf-tags/container-device-interface` library. At wrap time, `cdi.requestedDevices` FQDNs are filtered through the admin `allowDevices`/`denyDevices` policy (exact or `kind=*` patterns; deny wins), resolved into merged `ContainerEdits`, and translated by `cdi-translate.ts` into `--setenv` / `--dev-bind` / `--ro-bind` / `--bind` bwrap flags appended by `wrapCommandWithSandboxLinux`.

Unsupported CDI fields (`hooks`, `intelRdt`, `additionalGids`, `netDevices`) emit a one-shot warning and are dropped. macOS and Windows: a single warning, no CDI flags applied.

### `vendor/srt-win/` (Windows, in-progress)

Standalone Rust crate building `srt-win.exe`. Subcommands: `install`/`uninstall` (combined group + WFP), `group`, `wfp`, `exec`. Built and smoke-tested in CI on `windows-latest` and `windows-11-arm` (see `.github/workflows/integration-tests.yml`), but not yet imported from the TS layer. Cargo lives entirely under `vendor/srt-win/` — its `Cargo.toml` is not part of any workspace.

## Conventions worth knowing

- Debug logging is gated on `SRT_DEBUG` (not `DEBUG`, to avoid clashing with the npm `debug` package). `logForDebugging()` in `utils/debug.ts` is the single sink.
- The CLI shell-quotes argv-form invocations because the final exec is `bash -c <string>` — `.join(' ')` would corrupt args containing whitespace. `-c` mode passes the string through verbatim.
- Tests use `bun:test` (`describe`, `it`/`test`, `expect`, `beforeAll`, `afterAll`). The test tsconfig is `tsconfig.test.json`.
- Use `test/helpers/spawn.ts:spawnAsync` instead of `spawnSync` whenever the spawned command will talk to the in-process HTTP/SOCKS proxy — `spawnSync` blocks the event loop and self-deadlocks against the proxy. (Comment in that file explains the bun 1.3.2 carveout.)
- ESLint enforces `eqeqeq`, `consistent-type-imports` (inline), `switch-exhaustiveness-check`, `no-floating-promises`, and an `import/no-cycle` warning. Node-builtins rule is pinned to `>=18.0.0` with an allowlist for Web-standard `Request`/`Headers`/`ReadableStream` and `Readable.toWeb/fromWeb`.
- Prettier: no semis, single quotes, arrow parens avoid.

## Linux dev-environment gotcha

On Ubuntu 24.04+ runners and dev boxes:

```bash
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
```

Without this, `bwrap` creates a user namespace with zero capabilities and both the outer sandbox and `apply-seccomp` fail to nest further namespaces. The CI workflow does this; replicate it locally if `bwrap --ro-bind / / --unshare-net true` fails.
