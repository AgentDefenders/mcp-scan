import type { Finding, ScanResult } from '../types.js'

/**
 * Severity to GitHub Actions annotation level mapping.
 * GitHub Actions supports: error, warning, notice.
 */
const ANNOTATION_LEVEL: Record<string, string> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'notice',
}

/**
 * Print findings as GitHub Actions workflow annotations.
 * Each finding becomes a ::error:: or ::warning:: line that GitHub
 * renders inline in the Actions log and PR checks tab.
 */
export function printGitHubAnnotations(result: ScanResult): void {
  for (const finding of result.findings) {
    const level = ANNOTATION_LEVEL[finding.severity] || 'warning'
    const title = `[${finding.severity.toUpperCase()}] ${finding.analyzer}`
    const server = finding.server_name
    const tool = finding.tool_name && finding.tool_name !== '*' ? ` (tool: ${finding.tool_name})` : ''
    const msg = `${finding.description}${tool} [server: ${server}]`
    console.log(`::${level} title=${title}::${msg}`)
  }
}

/**
 * Write a markdown summary to $GITHUB_STEP_SUMMARY if the env var is set.
 * This renders a rich summary card in the GitHub Actions job view.
 */
export function writeStepSummary(result: ScanResult): void {
  const summaryPath = process.env.GITHUB_STEP_SUMMARY
  if (!summaryPath) return

  const fs = require('fs') as typeof import('fs')
  const lines: string[] = []

  lines.push(`## MCP Security Scan`)
  lines.push('')
  lines.push(`**Overall Grade:** ${result.overall_grade} | **Findings:** ${result.finding_count} | **Servers:** ${result.servers.length}`)
  lines.push('')

  if (result.findings.length > 0) {
    lines.push('| Severity | Analyzer | Server | Tool | Description |')
    lines.push('|----------|----------|--------|------|-------------|')
    for (const f of result.findings) {
      const tool = f.tool_name && f.tool_name !== '*' ? f.tool_name : '--'
      lines.push(`| ${f.severity.toUpperCase()} | ${f.analyzer} | ${f.server_name} | ${tool} | ${f.description} |`)
    }
    lines.push('')
  }

  lines.push('| Server | Grade | Tools |')
  lines.push('|--------|-------|-------|')
  for (const s of result.servers) {
    lines.push(`| ${s.server_name} | ${s.grade} | ${s.tool_count} |`)
  }
  lines.push('')
  lines.push(`*Scanned by [@agentdefenders/mcp-scan](https://agentdefenders.ai/mcp-scan) v${result.scanner_version}*`)

  try {
    fs.appendFileSync(summaryPath, lines.join('\n') + '\n')
  } catch {
    // GITHUB_STEP_SUMMARY path not writable -- skip silently.
  }
}
