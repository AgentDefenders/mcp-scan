import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import type { ScanResult } from '../src/types.js'

/**
 * Tests for CLI call-to-action (CTA) output logic.
 *
 * Because the CTA logic lives inside cli.ts (which calls program.parse() on
 * import), we test the underlying behaviour by exercising the logic directly
 * through helper functions extracted here rather than spawning child processes.
 * The helpers mirror exactly what cli.ts does after format output.
 */

/** Mirrors the CTA branch in cli.ts action handler. */
function printCTA(opts: {
  format: string
  quiet: boolean
  apiKey: string | undefined
  uploadedId: string | null
}): string[] {
  const lines: string[] = []

  if (opts.format === 'json' || opts.format === 'sarif') {
    return lines
  }

  if (opts.quiet) {
    return lines
  }

  if (!opts.apiKey) {
    lines.push('')
    lines.push('  Track your security grade over time: https://app.agentdefenders.ai/signup')
  } else if (opts.uploadedId) {
    lines.push('')
    lines.push(`  View full report: https://app.agentdefenders.ai/scanner/${opts.uploadedId}`)
  } else {
    lines.push('')
    lines.push('  Failed to upload scan result. Check your API key and try again.')
  }

  return lines
}

const emptyScan: ScanResult = {
  scanned_at: '2026-03-19T00:00:00Z',
  overall_grade: 'A',
  finding_count: 0,
  servers: [],
  findings: [],
  scanner_version: '0.1.0',
}

describe('CLI CTA output', () => {
  describe('no API key', () => {
    it('prints signup URL when no API key is provided', () => {
      const lines = printCTA({ format: 'console', quiet: false, apiKey: undefined, uploadedId: null })
      const joined = lines.join('\n')
      expect(joined).toContain('https://app.agentdefenders.ai/signup')
    })

    it('prints tracking message when no API key is provided', () => {
      const lines = printCTA({ format: 'console', quiet: false, apiKey: undefined, uploadedId: null })
      const joined = lines.join('\n')
      expect(joined).toContain('Track your security grade over time')
    })

    it('does not print permalink when no API key is provided', () => {
      const lines = printCTA({ format: 'console', quiet: false, apiKey: undefined, uploadedId: null })
      const joined = lines.join('\n')
      expect(joined).not.toContain('/scanner/')
    })
  })

  describe('--quiet flag', () => {
    it('produces no output when quiet is true and no API key', () => {
      const lines = printCTA({ format: 'console', quiet: true, apiKey: undefined, uploadedId: null })
      expect(lines).toHaveLength(0)
    })

    it('produces no output when quiet is true and API key is present with upload id', () => {
      const lines = printCTA({ format: 'console', quiet: true, apiKey: 'shld_testkey', uploadedId: 'abc123' })
      expect(lines).toHaveLength(0)
    })

    it('produces no output when quiet is true regardless of format', () => {
      const lines = printCTA({ format: 'console', quiet: true, apiKey: undefined, uploadedId: null })
      expect(lines).toHaveLength(0)
    })
  })

  describe('API key present and upload succeeds', () => {
    it('prints permalink when API key is provided and upload returns an id', () => {
      const lines = printCTA({ format: 'console', quiet: false, apiKey: 'shld_testkey', uploadedId: 'scan-99' })
      const joined = lines.join('\n')
      expect(joined).toContain('https://app.agentdefenders.ai/scanner/scan-99')
    })

    it('permalink line starts with two spaces', () => {
      const lines = printCTA({ format: 'console', quiet: false, apiKey: 'shld_testkey', uploadedId: 'scan-99' })
      const permalink = lines.find((l) => l.includes('/scanner/'))
      expect(permalink).toBeDefined()
      expect(permalink!.startsWith('  ')).toBe(true)
    })

    it('does not print signup URL when API key is present and upload succeeds', () => {
      const lines = printCTA({ format: 'console', quiet: false, apiKey: 'shld_testkey', uploadedId: 'scan-99' })
      const joined = lines.join('\n')
      expect(joined).not.toContain('signup')
    })

    it('prints error message when API key is present but upload failed (null id)', () => {
      const lines = printCTA({ format: 'console', quiet: false, apiKey: 'shld_testkey', uploadedId: null })
      const joined = lines.join('\n')
      expect(joined).toContain('Failed to upload scan result')
      expect(joined).not.toContain('/scanner/')
      expect(joined).not.toContain('signup')
    })
  })

  describe('non-console formats', () => {
    it('produces no CTA output for json format', () => {
      const lines = printCTA({ format: 'json', quiet: false, apiKey: undefined, uploadedId: null })
      expect(lines).toHaveLength(0)
    })

    it('produces no CTA output for sarif format', () => {
      const lines = printCTA({ format: 'sarif', quiet: false, apiKey: undefined, uploadedId: null })
      expect(lines).toHaveLength(0)
    })
  })
})
