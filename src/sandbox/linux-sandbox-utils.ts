import shellquote from 'shell-quote'
import { logForDebugging } from '../utils/debug.js'
import { whichSync } from '../utils/which.js'
import { randomBytes } from 'node:crypto'
import * as fs from 'fs'
import { execSync } from 'node:child_process'
import { tmpdir } from 'node:os'
import path, { join } from 'node:path'
import { ripGrep } from '../utils/ripgrep.js'
import {
  generateProxyEnvVars,
  normalizePathForSandbox,
  normalizeCaseForComparison,
  isSymlinkOutsideBoundary,
  DANGEROUS_FILES,
  getDangerousDirectories,
} from './sandbox-utils.js'
import type {
  FsReadRestrictionConfig,
  FsWriteRestrictionConfig,
} from './sandbox-schemas.js'
import {
  generateSeccompFilter,
  cleanupSeccompFilter,
  getPreGeneratedBpfPath,
  getApplySeccompBinaryPath,
} from './generate-seccomp-filter.js'

export interface LinuxNetworkBridgeContext {
  httpSocketPath: string
  socksSocketPath: string
  httpBridgePid: number
  socksBridgePid: number
  httpProxyPort: number
  socksProxyPort: number
}

/**
 * Check if a process with the given PID is still alive.
 */
export function isProcessAlive(pid: number): boolean {
  try {
    process.kill(pid, 0)
    return true
  } catch {
    return false
  }
}

/**
 * Spawn a socat bridge process via double-fork so it is fully detached from
 * the calling process tree.  This prevents the bun test runner (and similar
 * harnesses) from discovering and killing the bridge between test cases.
 *
 * The shell invocation:
 *   sh -c 'socat <args> & echo $!'
 *
 * 1. sh forks socat into the background (&)
 * 2. sh prints the socat PID and exits immediately
 * 3. socat is now orphaned and reparented to PID 1 – invisible to bun
 *
 * Returns the PID of the socat process.
 */
function spawnDetachedSocat(socatArgs: string[]): number {
  const quotedArgs = shellquote.quote(['socat', ...socatArgs])
  const cmd = `${quotedArgs} &\necho $!`
  const output = execSync(cmd, {
    shell: '/bin/sh',
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'ignore'],
  }).trim()
  const pid = parseInt(output, 10)
  if (isNaN(pid) || pid <= 0) {
    throw new Error(`Failed to parse socat PID from output: ${output}`)
  }
  return pid
}

export interface LinuxSandboxParams {
  command: string
  needsNetworkRestriction: boolean
  httpSocketPath?: string
  socksSocketPath?: string
  httpProxyPort?: number
  socksProxyPort?: number
  readConfig?: FsReadRestrictionConfig
  writeConfig?: FsWriteRestrictionConfig
  enableWeakerNestedSandbox?: boolean
  allowAllUnixSockets?: boolean
  binShell?: string
  ripgrepConfig?: { command: string; args?: string[] }
  /** Maximum directory depth to search for dangerous files (default: 3) */
  mandatoryDenySearchDepth?: number
  /** Allow writes to .git/config files (default: false) */
  allowGitConfig?: boolean
  /** Custom seccomp binary paths */
  seccompConfig?: { bpfPath?: string; applyPath?: string }
  /** Abort signal to cancel the ripgrep scan */
  abortSignal?: AbortSignal
}

/** Default max depth for searching dangerous files */
const DEFAULT_MANDATORY_DENY_SEARCH_DEPTH = 3

/**
 * Find if any component of the path is a symlink within the allowed write paths.
 * Returns the symlink path if found, or null if no symlinks.
 *
 * This is used to detect and block symlink replacement attacks where an attacker
 * could delete a symlink and create a real directory with malicious content.
 */
function findSymlinkInPath(
  targetPath: string,
  allowedWritePaths: string[],
): string | null {
  const parts = targetPath.split(path.sep)
  let currentPath = ''

  for (const part of parts) {
    if (!part) continue // Skip empty parts (leading /)
    const nextPath = currentPath + path.sep + part

    try {
      const stats = fs.lstatSync(nextPath)
      if (stats.isSymbolicLink()) {
        // Check if this symlink is within an allowed write path
        const isWithinAllowedPath = allowedWritePaths.some(
          allowedPath =>
            nextPath.startsWith(allowedPath + '/') || nextPath === allowedPath,
        )
        if (isWithinAllowedPath) {
          return nextPath
        }
      }
    } catch {
      // Path doesn't exist - no symlink issue here
      break
    }
    currentPath = nextPath
  }

  return null
}

/**
 * Check if any existing component in the path is a file (not a directory).
 * If so, the target path can never be created because you can't mkdir under a file.
 *
 * This handles the git worktree case: .git is a file, so .git/hooks can never
 * exist and there's nothing to deny.
 */
function hasFileAncestor(targetPath: string): boolean {
  const parts = targetPath.split(path.sep)
  let currentPath = ''

  for (const part of parts) {
    if (!part) continue // Skip empty parts (leading /)
    const nextPath = currentPath + path.sep + part
    try {
      const stat = fs.statSync(nextPath)
      if (stat.isFile() || stat.isSymbolicLink()) {
        // This component exists as a file — nothing below it can be created
        return true
      }
    } catch {
      // Path doesn't exist — stop checking
      break
    }
    currentPath = nextPath
  }

  return false
}

/**
 * Find the first non-existent path component.
 * E.g., for "/existing/parent/nonexistent/child/file.txt" where /existing/parent exists,
 * returns "/existing/parent/nonexistent"
 *
 * This is used to block creation of non-existent deny paths by mounting /dev/null
 * at the first missing component, preventing mkdir from creating the parent directories.
 */
function findFirstNonExistentComponent(targetPath: string): string {
  const parts = targetPath.split(path.sep)
  let currentPath = ''

  for (const part of parts) {
    if (!part) continue // Skip empty parts (leading /)
    const nextPath = currentPath + path.sep + part
    if (!fs.existsSync(nextPath)) {
      return nextPath
    }
    currentPath = nextPath
  }

  return targetPath // Shouldn't reach here if called correctly
}

/**
 * Get mandatory deny paths using ripgrep (Linux only).
 * Uses a SINGLE ripgrep call with multiple glob patterns for efficiency.
 * With --max-depth limiting, this is fast enough to run on each command without memoization.
 */
async function linuxGetMandatoryDenyPaths(
  ripgrepConfig: { command: string; args?: string[] } = { command: 'rg' },
  maxDepth: number = DEFAULT_MANDATORY_DENY_SEARCH_DEPTH,
  allowGitConfig = false,
  abortSignal?: AbortSignal,
): Promise<string[]> {
  const cwd = process.cwd()
  // Use provided signal or create a fallback controller
  const fallbackController = new AbortController()
  const signal = abortSignal ?? fallbackController.signal
  const dangerousDirectories = getDangerousDirectories()

  // Note: Settings files are added at the callsite in sandbox-manager.ts
  const denyPaths = [
    // Dangerous files in CWD
    ...DANGEROUS_FILES.map(f => path.resolve(cwd, f)),
    // Dangerous directories in CWD
    ...dangerousDirectories.map(d => path.resolve(cwd, d)),
  ]

  // Git hooks and config are only denied when .git exists as a directory.
  // In git worktrees, .git is a file (e.g., "gitdir: /path/..."), so
  // .git/hooks can never exist — denying it would cause bwrap to fail.
  // When .git doesn't exist at all, mounting at .git would block its
  // creation and break git init.
  const dotGitPath = path.resolve(cwd, '.git')
  let dotGitIsDirectory = false
  try {
    dotGitIsDirectory = fs.statSync(dotGitPath).isDirectory()
  } catch {
    // .git doesn't exist
  }

  if (dotGitIsDirectory) {
    // Git hooks always blocked for security
    denyPaths.push(path.resolve(cwd, '.git/hooks'))

    // Git config conditionally blocked based on allowGitConfig setting
    if (!allowGitConfig) {
      denyPaths.push(path.resolve(cwd, '.git/config'))
    }
  }

  // Build iglob args for all patterns in one ripgrep call
  const iglobArgs: string[] = []
  for (const fileName of DANGEROUS_FILES) {
    iglobArgs.push('--iglob', fileName)
  }
  for (const dirName of dangerousDirectories) {
    iglobArgs.push('--iglob', `**/${dirName}/**`)
  }
  // Git hooks always blocked in nested repos
  iglobArgs.push('--iglob', '**/.git/hooks/**')

  // Git config conditionally blocked in nested repos
  if (!allowGitConfig) {
    iglobArgs.push('--iglob', '**/.git/config')
  }

  // Single ripgrep call to find all dangerous paths in subdirectories
  // Limit depth for performance - deeply nested dangerous files are rare
  // and the security benefit doesn't justify the traversal cost
  let matches: string[] = []
  try {
    matches = await ripGrep(
      [
        '--files',
        '--hidden',
        '--max-depth',
        String(maxDepth),
        ...iglobArgs,
        '-g',
        '!**/node_modules/**',
      ],
      cwd,
      signal,
      ripgrepConfig,
    )
  } catch (error) {
    logForDebugging(`[Sandbox] ripgrep scan failed: ${error}`)
  }

  // Process matches
  for (const match of matches) {
    const absolutePath = path.resolve(cwd, match)

    // File inside a dangerous directory -> add the directory path
    let foundDir = false
    for (const dirName of [...dangerousDirectories, '.git']) {
      const normalizedDirName = normalizeCaseForComparison(dirName)
      const segments = absolutePath.split(path.sep)
      const dirIndex = segments.findIndex(
        s => normalizeCaseForComparison(s) === normalizedDirName,
      )
      if (dirIndex !== -1) {
        // For .git, we want hooks/ or config, not the whole .git dir
        if (dirName === '.git') {
          const gitDir = segments.slice(0, dirIndex + 1).join(path.sep)
          if (match.includes('.git/hooks')) {
            denyPaths.push(path.join(gitDir, 'hooks'))
          } else if (match.includes('.git/config')) {
            denyPaths.push(path.join(gitDir, 'config'))
          }
        } else {
          denyPaths.push(segments.slice(0, dirIndex + 1).join(path.sep))
        }
        foundDir = true
        break
      }
    }

    // Dangerous file match
    if (!foundDir) {
      denyPaths.push(absolutePath)
    }
  }

  return [...new Set(denyPaths)]
}

// Track generated seccomp filters for cleanup on process exit
const generatedSeccompFilters: Set<string> = new Set()

// Track mount points created by bwrap for non-existent deny paths.
// When bwrap does --ro-bind /dev/null /nonexistent/path, it creates an empty
// file on the host as a mount point. These persist after bwrap exits and must
// be cleaned up explicitly.
const bwrapMountPoints: Set<string> = new Set()

let exitHandlerRegistered = false

/**
 * Register cleanup handler for generated seccomp filters and bwrap mount points
 */
function registerExitCleanupHandler(): void {
  if (exitHandlerRegistered) {
    return
  }

  process.on('exit', () => {
    for (const filterPath of generatedSeccompFilters) {
      try {
        cleanupSeccompFilter(filterPath)
      } catch {
        // Ignore cleanup errors during exit
      }
    }
    cleanupBwrapMountPoints()
  })

  exitHandlerRegistered = true
}

/**
 * Clean up mount point files created by bwrap for non-existent deny paths.
 *
 * When protecting non-existent deny paths, bwrap creates empty files on the
 * host filesystem as mount points for --ro-bind. These files persist after
 * bwrap exits. This function removes them.
 *
 * This should be called after each sandboxed command completes to prevent
 * ghost dotfiles (e.g. .bashrc, .gitconfig) from appearing in the working
 * directory. It is also called automatically on process exit as a safety net.
 *
 * Safe to call at any time — it only removes files that were tracked during
 * generateFilesystemArgs() and skips any that no longer exist.
 */
export function cleanupBwrapMountPoints(): void {
  for (const mountPoint of bwrapMountPoints) {
    try {
      // Only remove if it's still the empty file/directory bwrap created.
      // If something else has written real content, leave it alone.
      const stat = fs.statSync(mountPoint)
      if (stat.isFile() && stat.size === 0) {
        fs.unlinkSync(mountPoint)
        logForDebugging(
          `[Sandbox Linux] Cleaned up bwrap mount point (file): ${mountPoint}`,
        )
      } else if (stat.isDirectory()) {
        // Empty directory mount points are created for intermediate
        // components (Fix 2). Only remove if still empty.
        const entries = fs.readdirSync(mountPoint)
        if (entries.length === 0) {
          fs.rmdirSync(mountPoint)
          logForDebugging(
            `[Sandbox Linux] Cleaned up bwrap mount point (dir): ${mountPoint}`,
          )
        }
      }
    } catch {
      // Ignore cleanup errors — the file may have already been removed
    }
  }
  bwrapMountPoints.clear()
}

/**
 * Detailed status of Linux sandbox dependencies
 */
export type LinuxDependencyStatus = {
  hasBwrap: boolean
  hasSocat: boolean
  hasSeccompBpf: boolean
  hasSeccompApply: boolean
}

/**
 * Result of checking sandbox dependencies
 */
export type SandboxDependencyCheck = {
  warnings: string[]
  errors: string[]
}

/**
 * Get detailed status of Linux sandbox dependencies
 */
export function getLinuxDependencyStatus(seccompConfig?: {
  bpfPath?: string
  applyPath?: string
}): LinuxDependencyStatus {
  return {
    hasBwrap: whichSync('bwrap') !== null,
    hasSocat: whichSync('socat') !== null,
    hasSeccompBpf: getPreGeneratedBpfPath(seccompConfig?.bpfPath) !== null,
    hasSeccompApply:
      getApplySeccompBinaryPath(seccompConfig?.applyPath) !== null,
  }
}

/**
 * Check sandbox dependencies and return structured result
 */
export function checkLinuxDependencies(seccompConfig?: {
  bpfPath?: string
  applyPath?: string
}): SandboxDependencyCheck {
  const errors: string[] = []
  const warnings: string[] = []

  if (whichSync('bwrap') === null)
    errors.push('bubblewrap (bwrap) not installed')
  if (whichSync('socat') === null) errors.push('socat not installed')

  const hasBpf = getPreGeneratedBpfPath(seccompConfig?.bpfPath) !== null
  const hasApply = getApplySeccompBinaryPath(seccompConfig?.applyPath) !== null
  if (!hasBpf || !hasApply) {
    warnings.push('seccomp not available - unix socket access not restricted')
  }

  return { warnings, errors }
}

/**
 * Initialize the Linux network bridge for sandbox networking
 *
 * ARCHITECTURE NOTE:
 * Linux network sandboxing uses bwrap --unshare-net which creates a completely isolated
 * network namespace with NO network access. To enable network access, we:
 *
 * 1. Host side: Run socat bridges that listen on Unix sockets and forward to host proxy servers
 *    - HTTP bridge: Unix socket -> host HTTP proxy (for HTTP/HTTPS traffic)
 *    - SOCKS bridge: Unix socket -> host SOCKS5 proxy (for SSH/git traffic)
 *
 * 2. Sandbox side: Bind the Unix sockets into the isolated namespace and run socat listeners
 *    - HTTP listener on port 3128 -> HTTP Unix socket -> host HTTP proxy
 *    - SOCKS listener on port 1080 -> SOCKS Unix socket -> host SOCKS5 proxy
 *
 * 3. Configure environment:
 *    - HTTP_PROXY=http://localhost:3128 for HTTP/HTTPS tools
 *    - GIT_SSH_COMMAND with socat for SSH through SOCKS5
 *
 * LIMITATION: Unlike macOS sandbox which can enforce domain-based allowlists at the kernel level,
 * Linux's --unshare-net provides only all-or-nothing network isolation. Domain filtering happens
 * at the host proxy level, not the sandbox boundary. This means network restrictions on Linux
 * depend on the proxy's filtering capabilities.
 *
 * DEPENDENCIES: Requires bwrap (bubblewrap) and socat
 */
export async function initializeLinuxNetworkBridge(
  httpProxyPort: number,
  socksProxyPort: number,
): Promise<LinuxNetworkBridgeContext> {
  const socketId = randomBytes(8).toString('hex')
  const httpSocketPath = join(tmpdir(), `claude-http-${socketId}.sock`)
  const socksSocketPath = join(tmpdir(), `claude-socks-${socketId}.sock`)

  // Start HTTP bridge via double-fork so the process is fully detached from
  // the parent process tree.  This prevents the bun test runner from killing
  // the bridge between test cases (it used to report "killed N dangling
  // processes" which removed the socket files and broke subsequent tests).
  const httpSocatArgs = [
    `UNIX-LISTEN:${httpSocketPath},fork,reuseaddr`,
    `TCP:localhost:${httpProxyPort},keepalive,keepidle=10,keepintvl=5,keepcnt=3`,
  ]

  logForDebugging(`Starting HTTP bridge: socat ${httpSocatArgs.join(' ')}`)

  let httpBridgePid: number
  try {
    httpBridgePid = spawnDetachedSocat(httpSocatArgs)
  } catch (err) {
    throw new Error(`Failed to start HTTP bridge process: ${err}`)
  }

  logForDebugging(`HTTP bridge started with PID ${httpBridgePid}`)

  // Start SOCKS bridge (same double-fork approach)
  const socksSocatArgs = [
    `UNIX-LISTEN:${socksSocketPath},fork,reuseaddr`,
    `TCP:localhost:${socksProxyPort},keepalive,keepidle=10,keepintvl=5,keepcnt=3`,
  ]

  logForDebugging(`Starting SOCKS bridge: socat ${socksSocatArgs.join(' ')}`)

  let socksBridgePid: number
  try {
    socksBridgePid = spawnDetachedSocat(socksSocatArgs)
  } catch (err) {
    // Clean up HTTP bridge
    try {
      process.kill(httpBridgePid, 'SIGTERM')
    } catch {
      // Ignore errors
    }
    throw new Error(`Failed to start SOCKS bridge process: ${err}`)
  }

  logForDebugging(`SOCKS bridge started with PID ${socksBridgePid}`)

  // Wait for both sockets to be ready
  const maxAttempts = 10
  for (let i = 0; i < maxAttempts; i++) {
    if (!isProcessAlive(httpBridgePid) || !isProcessAlive(socksBridgePid)) {
      throw new Error('Linux bridge process died unexpectedly')
    }

    try {
      if (fs.existsSync(httpSocketPath) && fs.existsSync(socksSocketPath)) {
        logForDebugging(`Linux bridges ready after ${i + 1} attempts`)
        break
      }
    } catch (err) {
      logForDebugging(`Error checking sockets (attempt ${i + 1}): ${err}`, {
        level: 'error',
      })
    }

    if (i === maxAttempts - 1) {
      // Clean up both processes
      try {
        process.kill(httpBridgePid, 'SIGTERM')
      } catch {
        // Ignore errors
      }
      try {
        process.kill(socksBridgePid, 'SIGTERM')
      } catch {
        // Ignore errors
      }
      throw new Error(
        `Failed to create bridge sockets after ${maxAttempts} attempts`,
      )
    }

    await new Promise(resolve => setTimeout(resolve, 100 + i * 100))
  }

  return {
    httpSocketPath,
    socksSocketPath,
    httpBridgePid,
    socksBridgePid,
    httpProxyPort,
    socksProxyPort,
  }
}

/**
 * Build the command that runs inside the sandbox.
 * Sets up HTTP proxy on port 3128 and SOCKS proxy on port 1080
 */
function buildSandboxCommand(
  httpSocketPath: string,
  socksSocketPath: string,
  userCommand: string,
  seccompFilterPath: string | undefined,
  shell?: string,
  writablePaths?: string[],
): string {
  // Default to bash for backward compatibility
  const shellPath = shell || 'bash'
  const socatCommands = [
    `socat TCP-LISTEN:3128,fork,reuseaddr UNIX-CONNECT:${httpSocketPath} >/dev/null 2>&1 &`,
    `socat TCP-LISTEN:1080,fork,reuseaddr UNIX-CONNECT:${socksSocketPath} >/dev/null 2>&1 &`,
    'trap "kill %1 %2 2>/dev/null; exit" EXIT',
  ]

  // If seccomp filter is provided, use a nested bwrap to apply it
  if (seccompFilterPath) {
    // Nested bwrap approach for seccomp isolation:
    //
    // Stage 1: Outer bwrap/bash (already running, no seccomp):
    //   - Starts socat processes that use socket(AF_UNIX,...) to connect to the
    //     Unix socket bridges. These processes are NOT subject to seccomp.
    //
    // Stage 2: Inner bwrap (--share-net + --seccomp fd):
    //   - Shares the outer bwrap's already-isolated network namespace, so the
    //     user command can still reach socat's TCP listeners on :3128 / :1080.
    //   - Applies the seccomp BPF filter via bwrap's --seccomp flag, which sets
    //     PR_SET_NO_NEW_PRIVS and loads the filter before exec-ing the child.
    //   - The user command (and only the user command) runs with Unix socket
    //     creation blocked.
    //
    // This solves the critical bug with the old apply-seccomp approach:
    //   When apply-seccomp called prctl(PR_SET_SECCOMP) and then exec'd the shell,
    //   socat's fork() children (spawned on each new TCP connection) inherited the
    //   seccomp filter. Those children then failed when trying to socket(AF_UNIX,...)
    //   to relay traffic through the Unix bridge, causing all proxy responses to be
    //   silently dropped and every proxied request to hang/timeout.
    //
    // With nested bwrap, the outer bash (and its socat children) never have the
    // seccomp filter applied; only the inner bwrap's child process tree does.
    //
    // The inner bwrap uses:
    //   --unshare-all   isolate all namespaces by default
    //   --share-net     re-share the outer bwrap's network namespace (so socat
    //                   TCP listeners on localhost:3128/1080 are reachable)
    //   --ro-bind / /   inherit the outer bwrap's root filesystem view
    //   --dev /dev      expose device nodes
    //   --seccomp 3     load BPF filter from fd 3 (opened via shell redirection)
    //
    // The BPF filter file is opened onto fd 3 with a shell here-string redirect
    // (`exec 3< filter.bpf`) before invoking bwrap, so bwrap can read it at
    // startup (before exec-ing the child) and then close it.

    // Build inner bwrap args: start with read-only root, then layer writable
    // bind mounts on top so the user command can write to allowed directories.
    // Without this the inner --ro-bind / / would shadow the outer bwrap's
    // writable mounts and every write would fail with EROFS.
    const innerBwrapArgs: string[] = [
      'bwrap',
      '--unshare-all',
      '--share-net',
      '--ro-bind',
      '/',
      '/',
    ]

    // Replicate writable bind mounts from the outer bwrap so writes succeed.
    // Skip /dev/* paths since --dev /dev already handles them (and paths like
    // /dev/stdout are symlinks that may not resolve inside the nested namespace).
    if (writablePaths) {
      for (const p of writablePaths) {
        if (p.startsWith('/dev/') || p === '/dev') {
          continue
        }
        if (fs.existsSync(p)) {
          innerBwrapArgs.push('--bind', p, p)
        }
      }
    }

    innerBwrapArgs.push(
      '--dev',
      '/dev',
      '--seccomp',
      '3',
      '--',
      shellPath,
      '-c',
      userCommand,
    )

    const innerBwrapCmd = shellquote.quote(innerBwrapArgs)

    // Open the BPF filter onto fd 3 before calling inner bwrap
    const innerScript = [
      ...socatCommands,
      // Wait a moment for socat listeners to be ready before starting the
      // user command, ensuring proxy traffic can flow immediately.
      'sleep 0.1',
      `exec 3< ${shellquote.quote([seccompFilterPath])}`,
      innerBwrapCmd,
    ].join('\n')

    return `${shellPath} -c ${shellquote.quote([innerScript])}`
  } else {
    // No seccomp filter - run user command directly
    const innerScript = [
      ...socatCommands,
      `eval ${shellquote.quote([userCommand])}`,
    ].join('\n')

    return `${shellPath} -c ${shellquote.quote([innerScript])}`
  }
}

/**
 * Generate filesystem bind mount arguments for bwrap
 */
async function generateFilesystemArgs(
  readConfig: FsReadRestrictionConfig | undefined,
  writeConfig: FsWriteRestrictionConfig | undefined,
  ripgrepConfig: { command: string; args?: string[] } = { command: 'rg' },
  mandatoryDenySearchDepth: number = DEFAULT_MANDATORY_DENY_SEARCH_DEPTH,
  allowGitConfig = false,
  abortSignal?: AbortSignal,
): Promise<string[]> {
  const args: string[] = []
  // fs already imported

  // Determine initial root mount based on write restrictions
  if (writeConfig) {
    // Write restrictions: Start with read-only root, then allow writes to specific paths
    args.push('--ro-bind', '/', '/')

    // Collect normalized allowed write paths for later checking
    const allowedWritePaths: string[] = []

    // Allow writes to specific paths
    for (const pathPattern of writeConfig.allowOnly || []) {
      const normalizedPath = normalizePathForSandbox(pathPattern)

      logForDebugging(
        `[Sandbox Linux] Processing write path: ${pathPattern} -> ${normalizedPath}`,
      )

      // Skip /dev/* paths since --dev /dev already handles them
      if (normalizedPath.startsWith('/dev/')) {
        logForDebugging(`[Sandbox Linux] Skipping /dev path: ${normalizedPath}`)
        continue
      }

      if (!fs.existsSync(normalizedPath)) {
        logForDebugging(
          `[Sandbox Linux] Skipping non-existent write path: ${normalizedPath}`,
        )
        continue
      }

      // Check if path is a symlink pointing outside expected boundaries
      // bwrap follows symlinks, so --bind on a symlink makes the target writable
      // This could unexpectedly expose paths the user didn't intend to allow
      try {
        const resolvedPath = fs.realpathSync(normalizedPath)
        // Trim trailing slashes before comparing: realpathSync never returns
        // a trailing slash, but normalizedPath may have one, which would cause
        // a false mismatch and incorrectly treat the path as a symlink.
        const normalizedForComparison = normalizedPath.replace(/\/+$/, '')
        if (
          resolvedPath !== normalizedForComparison &&
          isSymlinkOutsideBoundary(normalizedPath, resolvedPath)
        ) {
          logForDebugging(
            `[Sandbox Linux] Skipping symlink write path pointing outside expected location: ${pathPattern} -> ${resolvedPath}`,
          )
          continue
        }
      } catch {
        // realpathSync failed - path might not exist or be accessible, skip it
        logForDebugging(
          `[Sandbox Linux] Skipping write path that could not be resolved: ${normalizedPath}`,
        )
        continue
      }

      args.push('--bind', normalizedPath, normalizedPath)
      allowedWritePaths.push(normalizedPath)
    }

    // Deny writes within allowed paths (user-specified + mandatory denies)
    const denyPaths = [
      ...(writeConfig.denyWithinAllow || []),
      ...(await linuxGetMandatoryDenyPaths(
        ripgrepConfig,
        mandatoryDenySearchDepth,
        allowGitConfig,
        abortSignal,
      )),
    ]

    for (const pathPattern of denyPaths) {
      const normalizedPath = normalizePathForSandbox(pathPattern)

      // Skip /dev/* paths since --dev /dev already handles them
      if (normalizedPath.startsWith('/dev/')) {
        continue
      }

      // Check for symlinks in the path - if any parent component is a symlink,
      // mount /dev/null there to prevent symlink replacement attacks.
      // Attack scenario: .claude is a symlink to ./decoy/, attacker deletes
      // symlink and creates real .claude/settings.json with malicious hooks.
      const symlinkInPath = findSymlinkInPath(normalizedPath, allowedWritePaths)
      if (symlinkInPath) {
        args.push('--ro-bind', '/dev/null', symlinkInPath)
        logForDebugging(
          `[Sandbox Linux] Mounted /dev/null at symlink ${symlinkInPath} to prevent symlink replacement attack`,
        )
        continue
      }

      // Handle non-existent paths by mounting /dev/null to block creation.
      // Without this, a sandboxed process could mkdir+write a denied path that
      // doesn't exist yet, bypassing the deny rule entirely.
      //
      // bwrap creates empty files on the host as mount points for these binds.
      // We track them in bwrapMountPoints so cleanupBwrapMountPoints() can
      // remove them after the command exits.
      if (!fs.existsSync(normalizedPath)) {
        // Fix 1 (worktree): If any existing component in the deny path is a
        // file (not a directory), skip the deny entirely. You can't mkdir
        // under a file, so the deny path can never be created. This handles
        // git worktrees where .git is a file.
        if (hasFileAncestor(normalizedPath)) {
          logForDebugging(
            `[Sandbox Linux] Skipping deny path with file ancestor (cannot create paths under a file): ${normalizedPath}`,
          )
          continue
        }

        // Find the deepest existing ancestor directory
        let ancestorPath = path.dirname(normalizedPath)
        while (ancestorPath !== '/' && !fs.existsSync(ancestorPath)) {
          ancestorPath = path.dirname(ancestorPath)
        }

        // Only protect if the existing ancestor is within an allowed write path.
        // If not, the path is already read-only from --ro-bind / /.
        const ancestorIsWithinAllowedPath = allowedWritePaths.some(
          allowedPath =>
            ancestorPath.startsWith(allowedPath + '/') ||
            ancestorPath === allowedPath ||
            normalizedPath.startsWith(allowedPath + '/'),
        )

        if (ancestorIsWithinAllowedPath) {
          const firstNonExistent = findFirstNonExistentComponent(normalizedPath)

          // Fix 2: If firstNonExistent is an intermediate component (not the
          // leaf deny path itself), mount a read-only empty directory instead
          // of /dev/null. This prevents the component from appearing as a file
          // which breaks tools that expect to traverse it as a directory.
          if (firstNonExistent !== normalizedPath) {
            const emptyDir = fs.mkdtempSync(
              path.join(tmpdir(), 'claude-empty-'),
            )
            args.push('--ro-bind', emptyDir, firstNonExistent)
            bwrapMountPoints.add(firstNonExistent)
            registerExitCleanupHandler()
            logForDebugging(
              `[Sandbox Linux] Mounted empty dir at ${firstNonExistent} to block creation of ${normalizedPath}`,
            )
          } else {
            args.push('--ro-bind', '/dev/null', firstNonExistent)
            bwrapMountPoints.add(firstNonExistent)
            registerExitCleanupHandler()
            logForDebugging(
              `[Sandbox Linux] Mounted /dev/null at ${firstNonExistent} to block creation of ${normalizedPath}`,
            )
          }
        } else {
          logForDebugging(
            `[Sandbox Linux] Skipping non-existent deny path not within allowed paths: ${normalizedPath}`,
          )
        }
        continue
      }

      // Only add deny binding if this path is within an allowed write path
      // Otherwise it's already read-only from the initial --ro-bind / /
      const isWithinAllowedPath = allowedWritePaths.some(
        allowedPath =>
          normalizedPath.startsWith(allowedPath + '/') ||
          normalizedPath === allowedPath,
      )

      if (isWithinAllowedPath) {
        args.push('--ro-bind', normalizedPath, normalizedPath)
      } else {
        logForDebugging(
          `[Sandbox Linux] Skipping deny path not within allowed paths: ${normalizedPath}`,
        )
      }
    }
  } else {
    // No write restrictions: Allow all writes
    args.push('--bind', '/', '/')
  }

  // Handle read restrictions by mounting tmpfs over denied paths
  const readDenyPaths = [...(readConfig?.denyOnly || [])]

  // Always hide /etc/ssh/ssh_config.d to avoid permission issues with OrbStack
  // SSH is very strict about config file permissions and ownership, and they can
  // appear wrong inside the sandbox causing "Bad owner or permissions" errors
  if (fs.existsSync('/etc/ssh/ssh_config.d')) {
    readDenyPaths.push('/etc/ssh/ssh_config.d')
  }

  for (const pathPattern of readDenyPaths) {
    const normalizedPath = normalizePathForSandbox(pathPattern)
    if (!fs.existsSync(normalizedPath)) {
      logForDebugging(
        `[Sandbox Linux] Skipping non-existent read deny path: ${normalizedPath}`,
      )
      continue
    }

    const readDenyStat = fs.statSync(normalizedPath)
    if (readDenyStat.isDirectory()) {
      args.push('--tmpfs', normalizedPath)
    } else {
      // For files, bind /dev/null instead of tmpfs
      args.push('--ro-bind', '/dev/null', normalizedPath)
    }
  }

  return args
}

/**
 * Wrap a command with sandbox restrictions on Linux
 *
 * UNIX SOCKET BLOCKING (SECCOMP):
 * This implementation blocks Unix domain socket creation for user commands while
 * allowing the network infrastructure (socat bridges) to operate freely.
 *
 * When network restrictions are active (needsNetworkRestriction === true):
 *
 * Stage 1: Outer bwrap/bash - Network and filesystem isolation (NO seccomp)
 *   - Bubblewrap starts with isolated network namespace (--unshare-net)
 *   - Bubblewrap applies PID namespace isolation (--unshare-pid and --proc)
 *   - Filesystem restrictions are applied (read-only mounts, bind mounts, etc.)
 *   - Socat processes start and connect to Unix socket bridges (can use socket(AF_UNIX, ...))
 *
 * Stage 2: Inner (nested) bwrap - Seccomp filter application
 *   - A second bwrap is launched inside the outer shell with --share-net (to
 *     reuse the outer network namespace so socat's TCP listeners are reachable)
 *   - The seccomp BPF filter is loaded via bwrap's --seccomp flag, which sets
 *     PR_SET_NO_NEW_PRIVS and applies the filter before exec-ing the child
 *   - Writable bind mounts from the outer bwrap are replicated so writes succeed
 *   - Only the user command (and its children) run with seccomp active
 *
 * This nested-bwrap approach solves a critical bug with the previous apply-seccomp
 * binary approach: when apply-seccomp called prctl(PR_SET_SECCOMP) and then exec'd
 * the shell, socat's fork() children (spawned per TCP connection) inherited the
 * seccomp filter. Those children then failed when calling socket(AF_UNIX, ...) to
 * relay traffic through the Unix bridge, silently dropping all proxy responses.
 *
 * When network restrictions are NOT active but seccomp is needed:
 *   - The apply-seccomp binary is used directly since there are no socat processes
 *     whose children could inherit the filter.
 *
 * The seccomp-bpf filter blocks socket(AF_UNIX, ...) syscalls, preventing:
 * - Creating new Unix domain socket file descriptors
 *
 * Security limitations:
 * - Does NOT block operations (bind, connect, sendto, etc.) on inherited Unix socket FDs
 * - Does NOT prevent passing Unix socket FDs via SCM_RIGHTS
 * - For most sandboxing use cases, blocking socket creation is sufficient
 *
 * The filter allows:
 * - All TCP/UDP sockets (AF_INET, AF_INET6) for normal network operations
 * - All other syscalls
 *
 * PLATFORM NOTE:
 * The allowUnixSockets configuration is not path-based on Linux (unlike macOS)
 * because seccomp-bpf cannot inspect user-space memory to read socket paths.
 *
 * Requirements for seccomp filtering:
 * - Pre-built apply-seccomp binaries are included for x64 and ARM64 (used in
 *   the non-network-restricted path)
 * - Pre-generated BPF filters are included for x64 and ARM64
 * - Other architectures are not currently supported
 * - To use sandboxing without Unix socket blocking on unsupported architectures,
 *   set allowAllUnixSockets: true in your configuration
 * Dependencies are checked by checkLinuxDependencies() before enabling the sandbox.
 */
export async function wrapCommandWithSandboxLinux(
  params: LinuxSandboxParams,
): Promise<string> {
  const {
    command,
    needsNetworkRestriction,
    httpSocketPath,
    socksSocketPath,
    httpProxyPort,
    socksProxyPort,
    readConfig,
    writeConfig,
    enableWeakerNestedSandbox,
    allowAllUnixSockets,
    binShell,
    ripgrepConfig = { command: 'rg' },
    mandatoryDenySearchDepth = DEFAULT_MANDATORY_DENY_SEARCH_DEPTH,
    allowGitConfig = false,
    seccompConfig,
    abortSignal,
  } = params

  // Determine if we have restrictions to apply
  // Read: denyOnly pattern - empty array means no restrictions
  // Write: allowOnly pattern - undefined means no restrictions, any config means restrictions
  const hasReadRestrictions = readConfig && readConfig.denyOnly.length > 0
  const hasWriteRestrictions = writeConfig !== undefined

  // Check if we need any sandboxing
  if (
    !needsNetworkRestriction &&
    !hasReadRestrictions &&
    !hasWriteRestrictions
  ) {
    return command
  }

  const bwrapArgs: string[] = ['--new-session', '--die-with-parent']
  let seccompFilterPath: string | undefined = undefined

  try {
    // ========== SECCOMP FILTER (Unix Socket Blocking) ==========
    // Use bwrap's --seccomp flag to apply BPF filter that blocks Unix socket creation
    //
    // NOTE: Seccomp filtering is only enabled when allowAllUnixSockets is false
    // (when true, Unix sockets are allowed)
    if (!allowAllUnixSockets) {
      seccompFilterPath =
        generateSeccompFilter(seccompConfig?.bpfPath) ?? undefined
      const applySeccompBinary = getApplySeccompBinaryPath(
        seccompConfig?.applyPath,
      )

      if (!seccompFilterPath || !applySeccompBinary) {
        // Seccomp binaries not found - warn but continue without unix socket blocking
        logForDebugging(
          '[Sandbox Linux] Seccomp binaries not available - unix socket blocking disabled. ' +
            'Install @anthropic-ai/sandbox-runtime globally for full protection.',
          { level: 'warn' },
        )
        // Clear the filter path so we don't try to use it
        seccompFilterPath = undefined
      } else {
        // Track filter for cleanup and register exit handler
        // Only track runtime-generated filters (not pre-generated ones from vendor/)
        if (!seccompFilterPath.includes('/vendor/seccomp/')) {
          generatedSeccompFilters.add(seccompFilterPath)
          registerExitCleanupHandler()
        }

        logForDebugging(
          '[Sandbox Linux] Generated seccomp BPF filter for Unix socket blocking',
        )
      }
    } else {
      logForDebugging(
        '[Sandbox Linux] Skipping seccomp filter - allowAllUnixSockets is enabled',
      )
    }

    // ========== NETWORK RESTRICTIONS ==========
    if (needsNetworkRestriction) {
      // Always unshare network namespace to isolate network access
      // This removes all network interfaces, effectively blocking all network
      bwrapArgs.push('--unshare-net')

      // If proxy sockets are provided, bind them into the sandbox to allow
      // filtered network access through the proxy. If not provided, network
      // is completely blocked (empty allowedDomains = block all)
      if (httpSocketPath && socksSocketPath) {
        // Verify socket files still exist before trying to bind them
        if (!fs.existsSync(httpSocketPath)) {
          throw new Error(
            `Linux HTTP bridge socket does not exist: ${httpSocketPath}. ` +
              'The bridge process may have died. Try reinitializing the sandbox.',
          )
        }
        if (!fs.existsSync(socksSocketPath)) {
          throw new Error(
            `Linux SOCKS bridge socket does not exist: ${socksSocketPath}. ` +
              'The bridge process may have died. Try reinitializing the sandbox.',
          )
        }

        // Bind both sockets into the sandbox
        bwrapArgs.push('--bind', httpSocketPath, httpSocketPath)
        bwrapArgs.push('--bind', socksSocketPath, socksSocketPath)

        // Add proxy environment variables
        // HTTP_PROXY points to the socat listener inside the sandbox (port 3128)
        // which forwards to the Unix socket that bridges to the host's proxy server
        const proxyEnv = generateProxyEnvVars(
          3128, // Internal HTTP listener port
          1080, // Internal SOCKS listener port
        )
        bwrapArgs.push(
          ...proxyEnv.flatMap((env: string) => {
            const firstEq = env.indexOf('=')
            const key = env.slice(0, firstEq)
            const value = env.slice(firstEq + 1)
            return ['--setenv', key, value]
          }),
        )

        // Add host proxy port environment variables for debugging/transparency
        // These show which host ports the Unix socket bridges connect to
        if (httpProxyPort !== undefined) {
          bwrapArgs.push(
            '--setenv',
            'CLAUDE_CODE_HOST_HTTP_PROXY_PORT',
            String(httpProxyPort),
          )
        }
        if (socksProxyPort !== undefined) {
          bwrapArgs.push(
            '--setenv',
            'CLAUDE_CODE_HOST_SOCKS_PROXY_PORT',
            String(socksProxyPort),
          )
        }
      }
      // If no sockets provided, network is completely blocked (--unshare-net without proxy)
    }

    // ========== FILESYSTEM RESTRICTIONS ==========
    const fsArgs = await generateFilesystemArgs(
      readConfig,
      writeConfig,
      ripgrepConfig,
      mandatoryDenySearchDepth,
      allowGitConfig,
      abortSignal,
    )
    bwrapArgs.push(...fsArgs)

    // Always bind /dev
    bwrapArgs.push('--dev', '/dev')

    // ========== PID NAMESPACE ISOLATION ==========
    // IMPORTANT: These must come AFTER filesystem binds for nested bwrap to work
    // By default, always unshare PID namespace and mount fresh /proc.
    // If we don't have --unshare-pid, it is possible to escape the sandbox.
    // If we don't have --proc, it is possible to read host /proc and leak information about code running
    // outside the sandbox. But, --proc is not available when running in unprivileged docker containers
    // so we support running without it if explicitly requested.
    bwrapArgs.push('--unshare-pid')
    if (!enableWeakerNestedSandbox) {
      // Mount fresh /proc if PID namespace is isolated (secure mode)
      bwrapArgs.push('--proc', '/proc')
    }

    // ========== COMMAND ==========
    // Use the user's shell (zsh, bash, etc.) to ensure aliases/snapshots work
    // Resolve the full path to the shell binary since bwrap doesn't use $PATH
    const shellName = binShell || 'bash'
    const shell = whichSync(shellName)
    if (!shell) {
      throw new Error(`Shell '${shellName}' not found in PATH`)
    }
    bwrapArgs.push('--', shell, '-c')

    // If we have network restrictions, use the network bridge setup with apply-seccomp for seccomp
    // Otherwise, just run the command directly with apply-seccomp if needed
    if (needsNetworkRestriction && httpSocketPath && socksSocketPath) {
      // Pass seccomp filter to buildSandboxCommand for nested-bwrap application.
      // buildSandboxCommand starts socat bridges first (no seccomp), then launches
      // a nested bwrap with --share-net + --seccomp so only the user command is
      // subject to Unix socket blocking.
      // Collect writable paths so the inner bwrap can replicate them.
      // writeConfig.allowOnly already contains every path the outer bwrap
      // mounts as --bind (writable), so we just forward the list.
      const writablePaths = (writeConfig?.allowOnly ?? [])
        .map(p => normalizePathForSandbox(p))
        .filter(p => fs.existsSync(p))

      const sandboxCommand = buildSandboxCommand(
        httpSocketPath,
        socksSocketPath,
        command,
        seccompFilterPath,
        shell,
        writablePaths,
      )
      bwrapArgs.push(sandboxCommand)
    } else if (seccompFilterPath) {
      // No network restrictions but we have seccomp - use apply-seccomp directly
      // apply-seccomp is a simple C program that applies the seccomp filter and execs the command
      const applySeccompBinary = getApplySeccompBinaryPath(
        seccompConfig?.applyPath,
      )
      if (!applySeccompBinary) {
        throw new Error(
          'apply-seccomp binary not found. This should have been caught earlier. ' +
            'Ensure vendor/seccomp/{x64,arm64}/apply-seccomp binaries are included in the package.',
        )
      }

      const applySeccompCmd = shellquote.quote([
        applySeccompBinary,
        seccompFilterPath,
        shell,
        '-c',
        command,
      ])
      bwrapArgs.push(applySeccompCmd)
    } else {
      bwrapArgs.push(command)
    }

    // Build the outer bwrap command
    const wrappedCommand = shellquote.quote(['bwrap', ...bwrapArgs])

    const restrictions = []
    if (needsNetworkRestriction) restrictions.push('network')
    if (hasReadRestrictions || hasWriteRestrictions)
      restrictions.push('filesystem')
    if (seccompFilterPath) restrictions.push('seccomp(unix-block)')

    logForDebugging(
      `[Sandbox Linux] Wrapped command with bwrap (${restrictions.join(', ')} restrictions)`,
    )

    return wrappedCommand
  } catch (error) {
    // Clean up seccomp filter on error
    if (seccompFilterPath && !seccompFilterPath.includes('/vendor/seccomp/')) {
      generatedSeccompFilters.delete(seccompFilterPath)
      try {
        cleanupSeccompFilter(seccompFilterPath)
      } catch (cleanupError) {
        logForDebugging(
          `[Sandbox Linux] Failed to clean up seccomp filter on error: ${cleanupError}`,
          { level: 'error' },
        )
      }
    }
    // Re-throw the original error
    throw error
  }
}
