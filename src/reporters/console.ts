import type { ScanResult } from '../types.js'

const GRADE_COLORS: Record<string, string> = {
  A: '\x1b[32m',  // green
  B: '\x1b[32m',  // green
  C: '\x1b[33m',  // yellow
  D: '\x1b[33m',  // yellow (orange-ish)
  F: '\x1b[31m',  // red
}
const SEVERITY_COLORS: Record<string, string> = {
  critical: '\x1b[31m',
  high: '\x1b[33m',
  medium: '\x1b[36m',
  low: '\x1b[37m',
}
const RESET = '\x1b[0m'
const BOLD = '\x1b[1m'

function colorize(text: string, color: string): string {
  return `${color}${text}${RESET}`
}

/**
 * Print a human-readable scan report to stdout.
 * Uses ANSI color codes for terminal output.
 */
export function printConsoleReport(result: ScanResult): void {
  console.log('')
  console.log(`${BOLD}MCP Security Scan${RESET}  v${result.scanner_version}  ${new Date(result.scanned_at).toLocaleString()}`)
  console.log('')

  const gradeColor = GRADE_COLORS[result.overall_grade] || RESET
  console.log(`Overall grade: ${colorize(BOLD + result.overall_grade, gradeColor)}  (${result.finding_count} finding${result.finding_count !== 1 ? 's' : ''})`)
  console.log('')

  if (result.servers.length === 0) {
    console.log('No MCP servers found in supported client configurations.')
    console.log('')
    return
  }

  for (const server of result.servers) {
    const sg = GRADE_COLORS[server.grade] || RESET
    console.log(`  ${colorize(server.grade, sg)}  ${server.server_name}  (${server.tool_count} tool${server.tool_count !== 1 ? 's' : ''})`)

    if (server.findings.length === 0) {
      console.log(`       No issues found`)
    }

    for (const finding of server.findings) {
      const sc = SEVERITY_COLORS[finding.severity] || RESET
      console.log(`       ${colorize(finding.severity.toUpperCase(), sc)}  [${finding.analyzer}]  ${finding.tool_name}`)
      console.log(`              ${finding.description}`)
      if (finding.evidence && finding.evidence.length > 0) {
        const evidenceSnippet = finding.evidence.slice(0, 80)
        console.log(`              Evidence: ${evidenceSnippet}${finding.evidence.length > 80 ? '...' : ''}`)
      }
      if (finding.remediation) {
        console.log(`              Remediation: ${finding.remediation}`)
      }
    }
    console.log('')
  }

  if (result.finding_count === 0) {
    console.log(colorize('All clear. No security issues detected.', GRADE_COLORS['A']))
  }
  console.log('')
}
