// SPDX-License-Identifier: Apache-2.0
import { describe, test, expect, beforeEach, afterEach } from 'bun:test'
import type { ContainerEdits } from '@cncf-tags/container-device-interface'
import { cdiEditsToBwrapArgs } from '../../src/sandbox/cdi-translate.js'

describe('cdiEditsToBwrapArgs', () => {
  let warnings: string[]
  let originalWarn: typeof console.warn

  beforeEach(() => {
    warnings = []
    originalWarn = console.warn
    console.warn = (...args: unknown[]) => {
      warnings.push(args.map(String).join(' '))
    }
  })

  afterEach(() => {
    console.warn = originalWarn
  })

  test('empty edits produces empty args', () => {
    expect(cdiEditsToBwrapArgs({})).toEqual([])
    expect(warnings).toEqual([])
  })

  test('env: --setenv with first-= split', () => {
    const args = cdiEditsToBwrapArgs({
      env: ['NVIDIA_VISIBLE_DEVICES=0', 'CUDA_VERSION=11.8', 'WEIRD_VAL=a=b=c'],
    })
    expect(args).toEqual([
      '--setenv',
      'NVIDIA_VISIBLE_DEVICES',
      '0',
      '--setenv',
      'CUDA_VERSION',
      '11.8',
      '--setenv',
      'WEIRD_VAL',
      'a=b=c',
    ])
  })

  test('deviceNodes: --dev-bind with hostPath fallback to path', () => {
    const args = cdiEditsToBwrapArgs({
      deviceNodes: [
        { path: '/dev/nvidia0' },
        { path: '/dev/nvidia1', hostPath: '/dev/nvidia1' },
        { path: '/dev/in-container', hostPath: '/dev/on-host' },
      ],
    })
    expect(args).toEqual([
      '--dev-bind',
      '/dev/nvidia0',
      '/dev/nvidia0',
      '--dev-bind',
      '/dev/nvidia1',
      '/dev/nvidia1',
      '--dev-bind',
      '/dev/on-host',
      '/dev/in-container',
    ])
  })

  test('mounts with ro option → --ro-bind', () => {
    const args = cdiEditsToBwrapArgs({
      mounts: [
        {
          hostPath: '/usr/lib/libcuda.so.1',
          containerPath: '/usr/lib/libcuda.so.1',
          options: ['ro', 'bind'],
        },
      ],
    })
    expect(args).toEqual([
      '--ro-bind',
      '/usr/lib/libcuda.so.1',
      '/usr/lib/libcuda.so.1',
    ])
  })

  test('mounts without ro option → --bind', () => {
    const args = cdiEditsToBwrapArgs({
      mounts: [
        { hostPath: '/x', containerPath: '/y', options: ['bind'] },
        { hostPath: '/a', containerPath: '/b' },
      ],
    })
    expect(args).toEqual(['--bind', '/x', '/y', '--bind', '/a', '/b'])
  })

  test('hooks emit single warning and contribute no args', () => {
    const args = cdiEditsToBwrapArgs({
      hooks: [
        { hookName: 'createContainer', path: '/usr/bin/nvidia-ctk' },
        { hookName: 'createRuntime', path: '/usr/bin/x' },
      ],
    })
    expect(args).toEqual([])
    expect(warnings.length).toBe(1)
    expect(warnings[0]).toMatch(/hooks/i)
  })

  test('intelRdt emits single warning', () => {
    cdiEditsToBwrapArgs({ intelRdt: { closID: 'foo' } })
    expect(warnings.length).toBe(1)
    expect(warnings[0]).toMatch(/intelRdt/i)
  })

  test('additionalGids emits single warning', () => {
    cdiEditsToBwrapArgs({ additionalGids: [44, 55] })
    expect(warnings.length).toBe(1)
    expect(warnings[0]).toMatch(/additionalGids/i)
  })

  test('netDevices emits single warning', () => {
    cdiEditsToBwrapArgs({
      netDevices: [{ hostInterfaceName: 'eth0', name: 'eth0' }],
    })
    expect(warnings.length).toBe(1)
    expect(warnings[0]).toMatch(/netDevices/i)
  })

  test('order: env → deviceNodes → mounts (deterministic)', () => {
    const edits: ContainerEdits = {
      mounts: [{ hostPath: '/m', containerPath: '/m', options: ['ro'] }],
      env: ['A=1'],
      deviceNodes: [{ path: '/dev/x' }],
    }
    const args = cdiEditsToBwrapArgs(edits)
    expect(args).toEqual([
      '--setenv',
      'A',
      '1',
      '--dev-bind',
      '/dev/x',
      '/dev/x',
      '--ro-bind',
      '/m',
      '/m',
    ])
  })

  test('env entry without "=" is skipped with no crash', () => {
    const args = cdiEditsToBwrapArgs({ env: ['NOEQ', 'A=1'] })
    expect(args).toEqual(['--setenv', 'A', '1'])
  })
})
