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
