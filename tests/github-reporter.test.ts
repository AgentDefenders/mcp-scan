import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { printGitHubAnnotations, writeStepSummary } from '../src/reporters/github.js'
import type { ScanResult, Finding } from '../src/types.js'

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    analyzer: 'tool-poisoning',
    severity: 'high',
    server_name: 'test-server',
    tool_name: 'test-tool',
    description: 'Test finding description',
    field: 'description',
    evidence: 'suspicious content',
    remediation: 'Review the tool description',
    ...overrides,
  }
}

function makeResult(findings: Finding[] = []): ScanResult {
  return {
    scanned_at: '2026-03-27T00:00:00Z',
    overall_grade: findings.length > 0 ? 'D' : 'A',
    finding_count: findings.length,
    servers: [{
      server_name: 'test-server',
      grade: findings.length > 0 ? 'D' : 'A',
      tool_count: 3,
      findings,
    }],
    findings,
    scanner_version: '0.3.0',
  }
}

describe('printGitHubAnnotations', () => {
  let consoleSpy: ReturnType<typeof vi.spyOn>

  beforeEach(() => {
    consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {})
  })

  afterEach(() => {
    consoleSpy.mockRestore()
  })

  it('prints nothing for clean scan', () => {
    printGitHubAnnotations(makeResult())
    expect(consoleSpy).not.toHaveBeenCalled()
  })

  it('prints ::error:: for high severity findings', () => {
    printGitHubAnnotations(makeResult([makeFinding({ severity: 'high' })]))
    expect(consoleSpy).toHaveBeenCalledTimes(1)
    const output = consoleSpy.mock.calls[0][0] as string
    expect(output).toMatch(/^::error title=/)
    expect(output).toContain('[HIGH]')
    expect(output).toContain('tool-poisoning')
  })

  it('prints ::error:: for critical severity', () => {
    printGitHubAnnotations(makeResult([makeFinding({ severity: 'critical' })]))
    const output = consoleSpy.mock.calls[0][0] as string
    expect(output).toMatch(/^::error /)
  })

  it('prints ::warning:: for medium severity', () => {
    printGitHubAnnotations(makeResult([makeFinding({ severity: 'medium' })]))
    const output = consoleSpy.mock.calls[0][0] as string
    expect(output).toMatch(/^::warning /)
  })

  it('prints ::notice:: for low severity', () => {
    printGitHubAnnotations(makeResult([makeFinding({ severity: 'low' })]))
    const output = consoleSpy.mock.calls[0][0] as string
    expect(output).toMatch(/^::notice /)
  })

  it('includes server name in annotation message', () => {
    printGitHubAnnotations(makeResult([makeFinding({ server_name: 'my-mcp-server' })]))
    const output = consoleSpy.mock.calls[0][0] as string
    expect(output).toContain('[server: my-mcp-server]')
  })

  it('includes tool name when not wildcard', () => {
    printGitHubAnnotations(makeResult([makeFinding({ tool_name: 'run_query' })]))
    const output = consoleSpy.mock.calls[0][0] as string
    expect(output).toContain('(tool: run_query)')
  })

  it('omits tool name when wildcard', () => {
    printGitHubAnnotations(makeResult([makeFinding({ tool_name: '*' })]))
    const output = consoleSpy.mock.calls[0][0] as string
    expect(output).not.toContain('(tool:')
  })
})

describe('writeStepSummary', () => {
  it('does nothing when GITHUB_STEP_SUMMARY is not set', () => {
    delete process.env.GITHUB_STEP_SUMMARY
    // Should not throw.
    writeStepSummary(makeResult())
  })

  it('writes markdown summary when GITHUB_STEP_SUMMARY is set', () => {
    const fs = require('fs')
    const tmpFile = require('path').join(require('os').tmpdir(), `step-summary-${Date.now()}.md`)
    process.env.GITHUB_STEP_SUMMARY = tmpFile

    try {
      writeStepSummary(makeResult([makeFinding()]))
      const content = fs.readFileSync(tmpFile, 'utf8')
      expect(content).toContain('## MCP Security Scan')
      expect(content).toContain('Overall Grade')
      expect(content).toContain('test-server')
      expect(content).toContain('@agentdefenders/mcp-scan')
    } finally {
      delete process.env.GITHUB_STEP_SUMMARY
      try { fs.unlinkSync(tmpFile) } catch {}
    }
  })
})
