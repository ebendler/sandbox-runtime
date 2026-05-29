// SPDX-License-Identifier: Apache-2.0
import { describe, test, expect } from 'bun:test'
import { evaluatePolicy, type CdiPolicy } from '../../src/sandbox/cdi-policy.js'

describe('evaluatePolicy', () => {
  test('allow undefined + empty deny → allow anything', () => {
    const p: CdiPolicy = { allow: undefined, deny: [] }
    expect(evaluatePolicy('nvidia.com/gpu=0', p).decision).toBe('allow')
    expect(evaluatePolicy('vendor.com/xx=any', p).decision).toBe('allow')
  })

  test('allow empty array → deny everything', () => {
    const p: CdiPolicy = { allow: [], deny: [] }
    const r = evaluatePolicy('nvidia.com/gpu=0', p)
    expect(r.decision).toBe('deny')
    if (r.decision === 'deny') expect(r.reason).toMatch(/not in allowlist/i)
  })

  test('exact FQDN allow', () => {
    const p: CdiPolicy = { allow: ['nvidia.com/gpu=0'], deny: [] }
    expect(evaluatePolicy('nvidia.com/gpu=0', p).decision).toBe('allow')
    expect(evaluatePolicy('nvidia.com/gpu=1', p).decision).toBe('deny')
  })

  test('kind=* wildcard allow', () => {
    const p: CdiPolicy = { allow: ['nvidia.com/gpu=*'], deny: [] }
    expect(evaluatePolicy('nvidia.com/gpu=0', p).decision).toBe('allow')
    expect(evaluatePolicy('nvidia.com/gpu=foo-bar', p).decision).toBe('allow')
    expect(evaluatePolicy('amd.com/gpu=0', p).decision).toBe('deny')
  })

  test('deny wins over allow', () => {
    const p: CdiPolicy = {
      allow: ['nvidia.com/gpu=*'],
      deny: ['nvidia.com/gpu=1'],
    }
    expect(evaluatePolicy('nvidia.com/gpu=0', p).decision).toBe('allow')
    const r = evaluatePolicy('nvidia.com/gpu=1', p)
    expect(r.decision).toBe('deny')
    if (r.decision === 'deny') expect(r.reason).toMatch(/denylist/i)
  })

  test('deny wildcard', () => {
    const p: CdiPolicy = { allow: undefined, deny: ['amd.com/gpu=*'] }
    expect(evaluatePolicy('amd.com/gpu=0', p).decision).toBe('deny')
    expect(evaluatePolicy('nvidia.com/gpu=0', p).decision).toBe('allow')
  })

  test('malformed FQDN input → deny with reason', () => {
    const p: CdiPolicy = { allow: undefined, deny: [] }
    const r = evaluatePolicy('not-a-fqdn', p)
    expect(r.decision).toBe('deny')
    if (r.decision === 'deny') expect(r.reason).toMatch(/invalid/i)
  })
})
