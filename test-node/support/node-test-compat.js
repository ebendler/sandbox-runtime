import {
  describe,
  it,
  test,
  before,
  after,
  beforeEach,
  afterEach,
} from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { readFile } from 'node:fs/promises'

export { describe, it, test, beforeEach, afterEach }
export const beforeAll = before
export const afterAll = after

function isStringContainingMatcher(value) {
  return (
    typeof value === 'object' &&
    value !== null &&
    value.__matcher === 'stringContaining'
  )
}

function matchExpected(actual, expected) {
  if (isStringContainingMatcher(expected)) {
    return typeof actual === 'string' && actual.includes(expected.value)
  }
  return Object.is(actual, expected)
}

function createMatchers(actual, negated = false) {
  const check = (condition, message) => {
    if (negated ? condition : !condition) {
      throw new assert.AssertionError({
        message,
        actual,
        expected: negated ? false : true,
      })
    }
  }

  return {
    get not() {
      return createMatchers(actual, !negated)
    },
    toBe(expected) {
      check(
        Object.is(actual, expected),
        `Expected ${actual} to${negated ? ' not' : ''} be ${expected}`,
      )
    },
    toEqual(expected) {
      let passed = true
      try {
        assert.deepStrictEqual(actual, expected)
      } catch {
        passed = false
      }
      check(passed, 'Deep equality assertion failed')
    },
    toContain(expected) {
      const passed =
        typeof actual === 'string'
          ? actual.includes(expected)
          : Array.isArray(actual)
            ? actual.includes(expected)
            : false
      check(
        passed,
        `Expected value to${negated ? ' not' : ''} contain ${expected}`,
      )
    },
    toMatch(expected) {
      const regex = expected instanceof RegExp ? expected : new RegExp(expected)
      check(
        regex.test(String(actual)),
        `Expected value to${negated ? ' not' : ''} match ${regex}`,
      )
    },
    toBeNull() {
      check(
        actual === null,
        `Expected value to${negated ? ' not' : ''} be null`,
      )
    },
    toBeUndefined() {
      check(
        actual === undefined,
        `Expected value to${negated ? ' not' : ''} be undefined`,
      )
    },
    toBeDefined() {
      check(
        actual !== undefined,
        `Expected value to${negated ? ' not' : ''} be defined`,
      )
    },
    toBeTruthy() {
      check(
        Boolean(actual),
        `Expected value to${negated ? ' not' : ''} be truthy`,
      )
    },
    toBeFalsy() {
      check(!actual, `Expected value to${negated ? ' not' : ''} be falsy`)
    },
    toHaveLength(expected) {
      check(
        actual?.length === expected,
        `Expected length to${negated ? ' not' : ''} be ${expected}`,
      )
    },
    toHaveProperty(prop) {
      const passed = Object.prototype.hasOwnProperty.call(actual, prop)
      check(
        passed,
        `Expected object to${negated ? ' not' : ''} have property ${prop}`,
      )
    },
    toBeGreaterThan(expected) {
      check(
        actual > expected,
        `Expected ${actual} to${negated ? ' not' : ''} be greater than ${expected}`,
      )
    },
    toBeLessThan(expected) {
      check(
        actual < expected,
        `Expected ${actual} to${negated ? ' not' : ''} be less than ${expected}`,
      )
    },
    toThrow() {
      let threw = false
      try {
        actual()
      } catch {
        threw = true
      }
      check(threw, `Expected function to${negated ? ' not' : ''} throw`)
    },
    toHaveBeenCalledWith(...expectedArgs) {
      const calls = actual?.mock?.calls ?? []
      const passed = calls.some(call => {
        if (call.length !== expectedArgs.length) return false
        return call.every((arg, index) =>
          matchExpected(arg, expectedArgs[index]),
        )
      })
      check(
        passed,
        `Expected spy to${negated ? ' not' : ''} be called with matching args`,
      )
    },
  }
}

export function expect(actual) {
  return createMatchers(actual)
}

expect.stringContaining = value => ({ __matcher: 'stringContaining', value })

function createSpy(target, methodName) {
  const original = target[methodName]
  const calls = []
  let implementation = (...args) => original.apply(target, args)

  const spy = function (...args) {
    calls.push(args)
    return implementation(...args)
  }

  spy.mock = { calls }
  spy.mockImplementation = fn => {
    implementation = fn
    return spy
  }
  spy.mockRestore = () => {
    target[methodName] = original
  }

  target[methodName] = spy
  return spy
}

export const vi = {
  spyOn(target, methodName) {
    return createSpy(target, methodName)
  },
}

export const mock = {
  module(_specifier, factory) {
    const mod = factory?.()
    return mod
  },
}

if (typeof globalThis.Bun === 'undefined') {
  globalThis.Bun = {
    which(bin) {
      const result = spawnSync('which', [bin], {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'ignore'],
        timeout: 1000,
      })
      if (result.status === 0 && result.stdout) {
        return result.stdout.trim()
      }
      return null
    },
    file(path) {
      return {
        async text() {
          return readFile(path, 'utf8')
        },
      }
    },
  }
}
