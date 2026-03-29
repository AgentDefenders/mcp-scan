import { describe, it, expect, vi } from 'vitest'
import { printConsoleReport, printBanner } from '../src/reporters/console.js'
import type { ScanResult } from '../src/types.js'

/** Strip ANSI escape codes from a string. */
function stripAnsi(s: string): string {
  return s.replace(/\u001b\[[0-9;]*m/g, '')
}

/** Capture all console.log output during a printConsoleReport call. */
function captureOutput(result: ScanResult): string[] {
  const lines: string[] = []
  const spy = vi.spyOn(console, 'log').mockImplementation((...args: unknown[]) => {
    lines.push(args.map(String).join(' '))
  })
  printConsoleReport(result)
  spy.mockRestore()
  return lines
}

/** Capture output and strip ANSI codes for assertions. */
function captureCleanOutput(result: ScanResult): string {
  return stripAnsi(captureOutput(result).join('\n'))
}

const cleanScan: ScanResult = {
  scanned_at: '2026-03-26T00:00:00Z',
  overall_grade: 'A',
  finding_count: 0,
  servers: [
    {
      server_name: 'filesystem',
      grade: 'A',
      tool_count: 3,
      findings: [],
    },
  ],
  findings: [],
  scanner_version: '0.2.0',
  summary: {
    total_servers: 1,
    total_tools_analyzed: 3,
    servers_with_findings: 0,
    servers_clean: 1,
    clients_discovered: ['claude'],
    known_threats_checked: 20,
    scan_duration_ms: 50,
  },
}

const configOnlyScan: ScanResult = {
  scanned_at: '2026-03-26T00:00:00Z',
  overall_grade: 'A',
  finding_count: 0,
  servers: [
    {
      server_name: 'my-server',
      grade: 'A',
      tool_count: 0,
      findings: [],
    },
  ],
  findings: [],
  scanner_version: '0.2.0',
}

const scanWithFindings: ScanResult = {
  scanned_at: '2026-03-26T00:00:00Z',
  overall_grade: 'F',
  finding_count: 1,
  servers: [
    {
      server_name: 'evil-server',
      grade: 'F',
      tool_count: 2,
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
      ],
    },
  ],
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
  ],
  scanner_version: '0.2.0',
}

const scanWithSummary: ScanResult = {
  scanned_at: '2026-03-26T00:00:00Z',
  overall_grade: 'A',
  finding_count: 0,
  servers: [
    {
      server_name: 'server-a',
      grade: 'A',
      tool_count: 5,
      findings: [],
    },
    {
      server_name: 'server-b',
      grade: 'A',
      tool_count: 3,
      findings: [],
    },
  ],
  findings: [],
  scanner_version: '0.2.0',
  summary: {
    total_servers: 2,
    total_tools_analyzed: 8,
    servers_with_findings: 0,
    servers_clean: 2,
    clients_discovered: ['claude', 'cursor'],
    known_threats_checked: 20,
    scan_duration_ms: 120,
  },
}

describe('printConsoleReport', () => {
  it('shows config-only indicator when server has 0 tools', () => {
    const lines = captureOutput(configOnlyScan)
    const output = lines.join('\n')
    expect(output).toContain('config-only')
  })

  it('shows server name and tool count for normal servers', () => {
    const lines = captureOutput(cleanScan)
    const output = lines.join('\n')
    expect(output).toContain('filesystem')
    expect(output).toContain('3 tools')
  })

  it('shows overall grade line', () => {
    const lines = captureOutput(cleanScan)
    const output = lines.join('\n')
    expect(output).toContain('Overall grade:')
    expect(output).toContain('0 findings')
  })

  it('shows finding details including severity, analyzer, and description', () => {
    const lines = captureOutput(scanWithFindings)
    const output = lines.join('\n')
    expect(output).toContain('CRITICAL')
    expect(output).toContain('tool-poisoning')
    expect(output).toContain('Zero-width Unicode')
  })

  it('shows remediation when present', () => {
    const lines = captureOutput(scanWithFindings)
    const output = lines.join('\n')
    expect(output).toContain('fix:')
    expect(output).toContain('Review the tool description')
  })

  it('shows pass checklist for clean servers', () => {
    const output = captureCleanOutput(cleanScan)
    // Compact format uses checkmarks with short analyzer names
    expect(output).toContain('poisoning')
    expect(output).toContain('injection')
    expect(output).toContain('shadowing')
    expect(output).toContain('env')
    expect(output).toContain('threats')
  })

  it('shows grade explanation for clean scan', () => {
    const lines = captureOutput(cleanScan)
    const output = lines.join('\n')
    expect(output).toContain('Grade')
    expect(output).toContain('No security issues detected')
  })

  it('shows scanner version in banner', () => {
    const lines: string[] = []
    const spy = vi.spyOn(console, 'log').mockImplementation((...args: unknown[]) => {
      lines.push(args.map(String).join(' '))
    })
    printBanner('0.2.2-alpha')
    spy.mockRestore()
    const output = lines.join('\n')
    expect(output).toContain('v0.2.2-alpha')
  })

  it('shows MCP Security Scan header', () => {
    const lines = captureOutput(cleanScan)
    const output = lines.join('\n')
    expect(output).toContain('MCP Security Scan')
  })

  it('handles empty server list gracefully', () => {
    const emptyScan: ScanResult = {
      scanned_at: '2026-03-26T00:00:00Z',
      overall_grade: 'A',
      finding_count: 0,
      servers: [],
      findings: [],
      scanner_version: '0.2.0',
    }
    const lines = captureOutput(emptyScan)
    const output = lines.join('\n')
    expect(output).toContain('No MCP servers found')
  })

  it('uses singular "tool" for servers with exactly 1 tool', () => {
    const singleToolScan: ScanResult = {
      scanned_at: '2026-03-26T00:00:00Z',
      overall_grade: 'A',
      finding_count: 0,
      servers: [
        {
          server_name: 'single',
          grade: 'A',
          tool_count: 1,
          findings: [],
        },
      ],
      findings: [],
      scanner_version: '0.2.0',
    }
    const lines = captureOutput(singleToolScan)
    const output = lines.join('\n')
    // Should show "1 tool" not "1 tools"
    expect(output).toMatch(/1 tool[^s]/)
  })

  it('uses singular "finding" for exactly 1 finding', () => {
    const lines = captureOutput(scanWithFindings)
    const output = lines.join('\n')
    // Should show "1 finding" not "1 findings"
    expect(output).toMatch(/1 finding[^s]/)
  })

  it('truncates evidence longer than 120 characters', () => {
    const longEvidence = 'A'.repeat(200)
    const longScan: ScanResult = {
      scanned_at: '2026-03-26T00:00:00Z',
      overall_grade: 'F',
      finding_count: 1,
      servers: [
        {
          server_name: 'test',
          grade: 'F',
          tool_count: 1,
          findings: [
            {
              analyzer: 'tool-poisoning',
              severity: 'critical',
              server_name: 'test',
              tool_name: 'tool',
              description: 'Test finding',
              field: 'description',
              evidence: longEvidence,
              remediation: '',
            },
          ],
        },
      ],
      findings: [
        {
          analyzer: 'tool-poisoning',
          severity: 'critical',
          server_name: 'test',
          tool_name: 'tool',
          description: 'Test finding',
          field: 'description',
          evidence: longEvidence,
          remediation: '',
        },
      ],
      scanner_version: '0.2.0',
    }
    const lines = captureOutput(longScan)
    const output = lines.join('\n')
    // Evidence should be truncated with ellipsis
    expect(output).toContain('...')
    // Should not contain the full 200-char string
    expect(output).not.toContain(longEvidence)
  })

  it('output contains ANSI escape codes by default', () => {
    const lines = captureOutput(cleanScan)
    const output = lines.join('\n')
    expect(output).toContain('\x1b[')
  })

  it('shows Summary section with stats', () => {
    const lines = captureOutput(scanWithSummary)
    const output = lines.join('\n')
    // Redesigned reporter uses compact inline stats, not labeled lines.
    expect(output).toContain('servers')
    expect(output).toContain('tools')
    expect(output).toContain('threats checked')
  })

  it('shows Recommendations section', () => {
    const lines = captureOutput(cleanScan)
    const output = lines.join('\n')
    expect(output).toContain('Recommendations')
  })

  it('shows [PASS] for non-failing analyzers even when findings exist', () => {
    const output = captureCleanOutput(scanWithFindings)
    // tool-poisoning has findings, but other analyzers should show as passing.
    // The redesigned reporter uses short names with checkmarks, not [PASS] labels.
    expect(output).toContain('injection')
    expect(output).toContain('shadowing')
    expect(output).toContain('threats')
  })
})
