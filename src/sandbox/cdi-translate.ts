// SPDX-License-Identifier: Apache-2.0
import type { ContainerEdits } from '@cncf-tags/container-device-interface'

/**
 * Translates merged CDI ContainerEdits into bwrap CLI args. Returns a fresh
 * array; does not mutate inputs.
 *
 * Output order is deterministic for testability:
 *   1. --setenv pairs (one per env var, split on first =)
 *   2. --dev-bind for each deviceNode (hostPath || path → path)
 *   3. --ro-bind or --bind for each mount (ro detected via options array)
 *
 * Unsupported edits (hooks, intelRdt, additionalGids, netDevices) emit a
 * single warning each via console.warn and are otherwise dropped.
 */
export function cdiEditsToBwrapArgs(edits: ContainerEdits): string[] {
  const args: string[] = []

  if (edits.env) {
    for (const v of edits.env) {
      const eq = v.indexOf('=')
      if (eq <= 0) continue
      const key = v.slice(0, eq)
      const value = v.slice(eq + 1)
      args.push('--setenv', key, value)
    }
  }

  if (edits.deviceNodes) {
    for (const dn of edits.deviceNodes) {
      const src = dn.hostPath ?? dn.path
      args.push('--dev-bind', src, dn.path)
    }
  }

  if (edits.mounts) {
    for (const m of edits.mounts) {
      const ro = m.options?.includes('ro') ?? false
      args.push(ro ? '--ro-bind' : '--bind', m.hostPath, m.containerPath)
    }
  }

  if (edits.hooks && edits.hooks.length > 0) {
    console.warn(
      `[Sandbox CDI] CDI hooks are not executed by srt; dropping ${edits.hooks.length} hook(s).`,
    )
  }
  if (edits.intelRdt !== undefined) {
    console.warn(
      '[Sandbox CDI] CDI intelRdt is not supported by srt; dropping.',
    )
  }
  if (edits.additionalGids && edits.additionalGids.length > 0) {
    console.warn(
      `[Sandbox CDI] CDI additionalGids is not supported by srt (would require setuid); dropping ${edits.additionalGids.length} gid(s).`,
    )
  }
  if (edits.netDevices && edits.netDevices.length > 0) {
    console.warn(
      `[Sandbox CDI] CDI netDevices is not supported by srt (conflicts with network sandbox); dropping ${edits.netDevices.length} interface(s).`,
    )
  }

  return args
}
