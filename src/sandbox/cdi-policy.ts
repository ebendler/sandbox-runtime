// SPDX-License-Identifier: Apache-2.0
import {
  isQualifiedName,
  parseQualifiedName,
} from '@cncf-tags/container-device-interface'

/** Default CDI spec discovery directories. */
export const DEFAULT_CDI_SPEC_DIRS = ['/etc/cdi', '/var/run/cdi'] as const

export interface CdiPolicy {
  /** Allowlist; undefined = allow anything not in deny. Empty array = deny everything. */
  allow: string[] | undefined
  /** Denylist; deny wins. */
  deny: string[]
}

export type PolicyDecision =
  | { decision: 'allow' }
  | { decision: 'deny'; reason: string }

/**
 * Evaluates whether a CDI FQDN is permitted under the given policy.
 * Order: validate input → check deny → check allow → default.
 */
export function evaluatePolicy(
  fqdn: string,
  policy: CdiPolicy,
): PolicyDecision {
  if (!isQualifiedName(fqdn)) {
    return {
      decision: 'deny',
      reason: `invalid CDI FQDN ${JSON.stringify(fqdn)}`,
    }
  }

  for (const pat of policy.deny) {
    if (matchesPattern(fqdn, pat)) {
      return {
        decision: 'deny',
        reason: `device ${JSON.stringify(fqdn)} matches denylist pattern ${JSON.stringify(pat)}`,
      }
    }
  }

  if (policy.allow === undefined) {
    return { decision: 'allow' }
  }

  for (const pat of policy.allow) {
    if (matchesPattern(fqdn, pat)) {
      return { decision: 'allow' }
    }
  }

  return {
    decision: 'deny',
    reason: `device ${JSON.stringify(fqdn)} not in allowlist`,
  }
}

/**
 * Matches a single pattern against an FQDN.
 * Patterns:
 *   - exact FQDN (e.g. "nvidia.com/gpu=0") — string equality.
 *   - kind-wildcard ("kind=*") — kind portion must equal the FQDN's kind exactly.
 */
function matchesPattern(fqdn: string, pattern: string): boolean {
  if (pattern.endsWith('=*')) {
    const kindPattern = pattern.slice(0, -2)
    const parsed = parseQualifiedName(fqdn)
    return parsed !== null && parsed.kind === kindPattern
  }
  return pattern === fqdn
}
