// SPDX-License-Identifier: Apache-2.0
import { describe, test, expect } from 'bun:test'
import { SandboxRuntimeConfigSchema } from '../../src/sandbox/sandbox-config.js'

const minimalBase = {
  network: { allowedDomains: [], deniedDomains: [] },
  filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
}

describe('CDI config schema', () => {
  test('omitted cdi field validates', () => {
    const r = SandboxRuntimeConfigSchema.safeParse({ ...minimalBase })
    expect(r.success).toBe(true)
  })

  test('empty cdi object validates', () => {
    const r = SandboxRuntimeConfigSchema.safeParse({
      ...minimalBase,
      cdi: {},
    })
    expect(r.success).toBe(true)
  })

  test('full cdi block with exact FQDN allow validates', () => {
    const r = SandboxRuntimeConfigSchema.safeParse({
      ...minimalBase,
      cdi: {
        specDirs: ['/etc/cdi', '/var/run/cdi'],
        requestedDevices: ['nvidia.com/gpu=0', 'nvidia.com/gpu=1'],
        allowDevices: ['nvidia.com/gpu=0'],
        denyDevices: [],
      },
    })
    expect(r.success).toBe(true)
  })

  test('kind=* trailing wildcard pattern validates', () => {
    const r = SandboxRuntimeConfigSchema.safeParse({
      ...minimalBase,
      cdi: {
        allowDevices: ['nvidia.com/gpu=*'],
      },
    })
    expect(r.success).toBe(true)
  })

  test('rejects allow pattern with malformed FQDN', () => {
    const r = SandboxRuntimeConfigSchema.safeParse({
      ...minimalBase,
      cdi: { allowDevices: ['not-an-fqdn'] },
    })
    expect(r.success).toBe(false)
  })

  test('rejects allow pattern with leading wildcard', () => {
    const r = SandboxRuntimeConfigSchema.safeParse({
      ...minimalBase,
      cdi: { allowDevices: ['*=foo'] },
    })
    expect(r.success).toBe(false)
  })

  test('rejects allow pattern with vendor wildcard', () => {
    const r = SandboxRuntimeConfigSchema.safeParse({
      ...minimalBase,
      cdi: { allowDevices: ['nvidia.com/*=*'] },
    })
    expect(r.success).toBe(false)
  })

  test('rejects requestedDevices entry that is not a qualified name', () => {
    const r = SandboxRuntimeConfigSchema.safeParse({
      ...minimalBase,
      cdi: { requestedDevices: ['plain-string'] },
    })
    expect(r.success).toBe(false)
  })

  test('denyDevices uses the same pattern syntax as allowDevices', () => {
    const r = SandboxRuntimeConfigSchema.safeParse({
      ...minimalBase,
      cdi: { denyDevices: ['nvidia.com/gpu=*', 'amd.com/gpu=0'] },
    })
    expect(r.success).toBe(true)
  })
})
