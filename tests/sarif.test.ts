import { describe, it, expect } from 'vitest'
import { formatSARIF } from '../src/reporters/sarif.js'
import type { ScanResult } from '../src/types.js'

const emptyScan: ScanResult = {
  scanned_at: '2026-03-19T00:00:00Z',
  overall_grade: 'A',
  finding_count: 0,
  servers: [],
  findings: [],
  scanner_version: '0.1.0',
}

const scanWithFindings: ScanResult = {
  scanned_at: '2026-03-19T00:00:00Z',
  overall_grade: 'F',
  finding_count: 2,
  servers: [],
  findings: [
    {
      analyzer: 'tool-poisoning',
      severity: 'critical',
      server_name: 'evil-server',
      tool_name: 'helper',
      description: 'Zero-width Unicode character detected in tool description',
      field: 'description',
      evidence: '\u200b',
      remediation: 'Review the tool description for hidden instructions.',
    },
    {
      analyzer: 'shadowing',
      severity: 'high',
      server_name: 'shadow-server',
      tool_name: 'bash',
      description: 'Tool name shadows built-in: bash',
      field: 'name',
      evidence: 'bash',
      remediation: 'Rename the tool or remove the duplicate MCP server.',
    },
  ],
  scanner_version: '0.1.0',
}

describe('formatSARIF', () => {
  it('produces valid SARIF 2.1.0 structure', () => {
    const sarif = JSON.parse(formatSARIF(emptyScan))
    expect(sarif.version).toBe('2.1.0')
    expect(sarif.$schema).toContain('sarif-2.1.0')
    expect(sarif.runs).toHaveLength(1)
    expect(sarif.runs[0].tool.driver.name).toBe('mcp-scan')
    expect(sarif.runs[0].tool.driver.version).toBe('0.1.0')
  })

  it('produces zero results for clean scan', () => {
    const sarif = JSON.parse(formatSARIF(emptyScan))
    expect(sarif.runs[0].results).toHaveLength(0)
  })

  it('maps critical findings to SARIF level error', () => {
    const sarif = JSON.parse(formatSARIF(scanWithFindings))
    const criticalResult = sarif.runs[0].results.find((r: { ruleId: string }) => r.ruleId === 'tool-poisoning')
    expect(criticalResult).toBeDefined()
    expect(criticalResult.level).toBe('error')
    expect(criticalResult.message.text).toContain('Zero-width Unicode')
  })

  it('maps high findings to SARIF level error', () => {
    const sarif = JSON.parse(formatSARIF(scanWithFindings))
    const highResult = sarif.runs[0].results.find((r: { ruleId: string; message: { text: string } }) => r.message.text.includes('bash'))
    expect(highResult.level).toBe('error')
  })

  it('maps medium findings to SARIF level warning', () => {
    const scan = { ...scanWithFindings, findings: [{ ...scanWithFindings.findings[0], severity: 'medium' as const }] }
    const sarif = JSON.parse(formatSARIF(scan))
    expect(sarif.runs[0].results[0].level).toBe('warning')
  })

  it('maps low findings to SARIF level note', () => {
    const scan = { ...scanWithFindings, findings: [{ ...scanWithFindings.findings[0], severity: 'low' as const }] }
    const sarif = JSON.parse(formatSARIF(scan))
    expect(sarif.runs[0].results[0].level).toBe('note')
  })

  it('populates rules from unique analyzer names', () => {
    const sarif = JSON.parse(formatSARIF(scanWithFindings))
    const rules: { id: string }[] = sarif.runs[0].tool.driver.rules
    const ruleIds = rules.map((r) => r.id)
    expect(ruleIds).toContain('tool-poisoning')
    expect(ruleIds).toContain('shadowing')
  })
})
