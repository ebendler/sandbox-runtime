import { describe, test, expect, spyOn, afterEach } from 'bun:test'
import { existsSync } from 'node:fs'
import * as fs from 'fs'
import { tmpdir } from 'node:os'
import { isLinux, isMacOS } from '../helpers/platform.js'
import {
  detectCudaAvailable,
  discoverCudaDevices,
  wrapCommandWithSandboxLinux,
} from '../../src/sandbox/linux-sandbox-utils.js'
import { wrapCommandWithSandboxMacOS } from '../../src/sandbox/macos-sandbox-utils.js'

describe.if(isMacOS)('detectCudaAvailable on macOS', () => {
  test('returns false', () => {
    expect(detectCudaAvailable()).toBe(false)
  })
})

describe.if(isLinux)('detectCudaAvailable on Linux', () => {
  test('returns existence of /dev/nvidiactl', () => {
    expect(detectCudaAvailable()).toBe(existsSync('/dev/nvidiactl'))
  })
})

describe.if(isLinux)('discoverCudaDevices (Linux)', () => {
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

  test('indexed nodes appear in numeric order after the fixed nodes', () => {
    const devices = discoverCudaDevices()
    const indexed = devices.filter(d => /^\/dev\/nvidia\d+$/.test(d))

    // Each entry must come after every preceding entry numerically.
    for (let i = 1; i < indexed.length; i++) {
      const prev = Number(indexed[i - 1].match(/\d+$/)![0])
      const curr = Number(indexed[i].match(/\d+$/)![0])
      expect(curr).toBeGreaterThan(prev)
    }

    // Indexed entries must appear after the fixed entries.
    if (indexed.length > 0) {
      const firstIndexedAt = devices.indexOf(indexed[0])
      const lastFixedAt = devices.indexOf('/dev/nvidia-caps')
      expect(firstIndexedAt).toBeGreaterThan(lastFixedAt)
    }
  })
})

describe.if(isLinux)('discoverCudaDevices readdir failure', () => {
  let readdirSpy: ReturnType<typeof spyOn>

  afterEach(() => {
    readdirSpy.mockRestore()
  })

  test('returns only fixed nodes when readdirSync throws', () => {
    readdirSpy = spyOn(fs, 'readdirSync').mockImplementation(
      (p: fs.PathLike | number) => {
        if (p === '/dev') {
          const err: NodeJS.ErrnoException = new Error('EACCES')
          err.code = 'EACCES'
          throw err
        }
        throw new Error(`unexpected readdirSync(${p})`)
      },
    )

    const devices = discoverCudaDevices()
    expect(devices).toEqual([
      '/dev/nvidiactl',
      '/dev/nvidia-uvm',
      '/dev/nvidia-uvm-tools',
      '/dev/nvidia-caps',
    ])
  })
})

describe.if(isMacOS)('discoverCudaDevices on macOS', () => {
  test('returns empty list (platform guard)', () => {
    expect(discoverCudaDevices()).toEqual([])
  })
})

describe.if(isLinux)('wrapCommandWithSandboxLinux CUDA arg emission', () => {
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
