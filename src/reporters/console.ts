import type { MCPServer, ScanResult, ServerScanResult } from '../types.js'
import { getKnownThreatCount } from '../analyzers/known-threats.js'

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
const DIM = '\x1b[2m'
const GREEN = '\x1b[32m'
const BRIGHT_GREEN = '\x1b[92m'
const CYAN = '\x1b[36m'
const WHITE = '\x1b[97m'

/** All analyzer names used to display the pass checklist for clean servers. */
const ALL_ANALYZERS = ['tool-poisoning', 'prompt-injection', 'shadowing', 'suspicious-env', 'known-threats'] as const

/** Human-readable client display names. */
const CLIENT_DISPLAY_NAMES: Record<string, string> = {
  claude: 'Claude Desktop',
  cursor: 'Cursor',
  vscode: 'VS Code',
  windsurf: 'Windsurf',
  gemini: 'Gemini CLI',
  cline: 'Cline',
  jetbrains: 'JetBrains',
  continue: 'Continue',
  antigravity: 'Antigravity',
  zed: 'Zed',
  amazonq: 'Amazon Q',
}

/** Grade explanation messages. */
const GRADE_EXPLANATIONS: Record<string, string> = {
  A: 'No security issues detected across all servers.',
  B: 'Minor issues detected. Low-severity findings only.',
  C: 'Moderate issues detected. Review medium-severity findings.',
  D: 'Significant issues detected. Address high-severity findings promptly.',
  F: 'Critical issues detected. Immediate action required.',
}

/** Static recommendations shown after every scan. */
const RECOMMENDATIONS = [
  'Pin MCP server versions to prevent supply-chain attacks',
  'Audit tool descriptions periodically (use --watch for continuous monitoring)',
  'Restrict environment variable access for MCP servers',
  'Review OWASP MCP Top 10: https://owasp.org/www-project-mcp-top-10/',
]

/**
 * Redact values in args that look like secrets.
 * If any arg contains 'key=', 'token=', 'secret=' or starts with 'sk-', 'shld_', replace with [REDACTED].
 */
function redactArg(arg: string): string {
  if (/(?:key|token|secret)=/i.test(arg)) {
    return arg.replace(/((?:key|token|secret)=).*/i, '$1[REDACTED]')
  }
  if (/^(?:sk-|shld_)/i.test(arg)) {
    return '[REDACTED]'
  }
  return arg
}

/**
 * Build a display string for the server command path.
 * Truncates to maxLen characters and redacts secrets in args.
 */
function formatCommandPath(server: ServerScanResult & { command?: string; args?: string[] }, maxLen: number): string {
  const cmd = server.command || ''
  if (!cmd) return ''
  const args = server.args || []
  const redactedArgs = args.map(redactArg)
  const full = [cmd, ...redactedArgs].join(' ')
  if (full.length <= maxLen) return full
  return full.slice(0, maxLen - 3) + '...'
}

/**
 * Determine transport type from server configuration.
 */
function inferTransport(server: ServerScanResult & { transport?: string }): string {
  if (server.transport) return server.transport
  return 'stdio'
}

function colorize(text: string, color: string): string {
  return `${color}${text}${RESET}`
}

/**
 * Print the AgentDefenders sentinel banner.
 * ASCII art shield inspired by the sentinel mark logo.
 * Only shown in interactive console mode, not --quiet or structured formats.
 */
export function printBanner(version: string): void {
  const g = BRIGHT_GREEN
  const c = CYAN
  const w = WHITE
  const d = DIM
  const r = RESET

  // Claude Code CLI style: clean single-line icon + bold product name + dim metadata.
  // The sentinel diamond is our brand mark, rendered as a simple inline glyph.
  const lines = [
    ``,
    `  ${g}◇${r} ${w}${BOLD}AgentDefenders${r} ${c}mcp-scan${r} ${d}v${version}${r}`,
    ``,
    `  ${d}MCP supply chain security scanner${r}`,
    `  ${d}Detects tool poisoning, prompt injection, shadowing, and known threats.${r}`,
    `  ${d}All analysis runs locally. No data leaves your machine.${r}`,
    ``,
  ]

  for (const line of lines) {
    console.log(line)
  }
}

/**
 * Print a human-readable scan report to stdout.
 * Uses ANSI color codes for terminal output.
 */
export function printConsoleReport(result: ScanResult, servers?: MCPServer[]): void {
  const knownThreatCount = getKnownThreatCount()

  // Build a lookup from server name to MCPServer for extra metadata.
  const serverMap = new Map<string, MCPServer>()
  if (servers) {
    for (const s of servers) {
      serverMap.set(s.name, s)
    }
  }

  // Derive client names from summary or server metadata.
  const clientNames: string[] = result.summary?.clients_discovered || []
  const clientDisplay = clientNames
    .map((c) => CLIENT_DISPLAY_NAMES[c] || c)
    .join(', ')

  console.log(`${BOLD}MCP Security Scan${RESET}  ${new Date(result.scanned_at).toLocaleString()}`)
  const clientSuffix = clientDisplay ? ` (${clientDisplay})` : ''
  console.log(`Scanned ${result.servers.length} server${result.servers.length !== 1 ? 's' : ''} across ${clientNames.length} client${clientNames.length !== 1 ? 's' : ''}${clientSuffix}`)
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
    const originalServer = serverMap.get(server.server_name)

    // Show "(config-only)" when tools is empty/undefined, otherwise show tool count.
    const toolLabel = server.tool_count === 0
      ? 'config-only'
      : `${server.tool_count} tool${server.tool_count !== 1 ? 's' : ''}`

    // Build command path display.
    const serverWithMeta = {
      ...server,
      command: originalServer?.command,
      args: originalServer?.args,
      transport: originalServer?.transport,
    }
    const cmdPath = formatCommandPath(serverWithMeta, 50)
    const transport = inferTransport(serverWithMeta)
    const cmdDisplay = cmdPath ? `  ${DIM}${cmdPath}${RESET}` : ''

    console.log(`  ${colorize(server.grade, sg)}  ${server.server_name}  (${toolLabel})${cmdDisplay}  ${DIM}[${transport}]${RESET}`)

    if (server.findings.length === 0) {
      // Show [PASS] checklist for all analyzers.
      for (const analyzer of ALL_ANALYZERS) {
        if (analyzer === 'known-threats') {
          console.log(`     ${colorize('[PASS]', GREEN)} ${analyzer} (checked against ${knownThreatCount} known threats)`)
        } else {
          console.log(`     ${colorize('[PASS]', GREEN)} ${analyzer}`)
        }
      }
    } else {
      // Show findings grouped by analyzer.
      const findingAnalyzers = new Set(server.findings.map((f) => f.analyzer))

      // Show passing analyzers first.
      for (const analyzer of ALL_ANALYZERS) {
        if (!findingAnalyzers.has(analyzer)) {
          if (analyzer === 'known-threats') {
            console.log(`     ${colorize('[PASS]', GREEN)} ${analyzer} (checked against ${knownThreatCount} known threats)`)
          } else {
            console.log(`     ${colorize('[PASS]', GREEN)} ${analyzer}`)
          }
        }
      }

      // Show findings.
      for (const finding of server.findings) {
        const sc = SEVERITY_COLORS[finding.severity] || RESET
        const toolSuffix = finding.tool_name && finding.tool_name !== '*' ? `  ${finding.tool_name}` : ''
        console.log(`     ${colorize(finding.severity.toUpperCase(), sc)}  ${finding.analyzer}${toolSuffix}`)
        console.log(`            ${finding.description}`)
        if (finding.evidence && finding.evidence.length > 0) {
          const evidenceSnippet = finding.evidence.slice(0, 120)
          console.log(`            Evidence: ${evidenceSnippet}${finding.evidence.length > 120 ? '...' : ''}`)
        }
        if (finding.remediation) {
          console.log(`            Remediation: ${finding.remediation}`)
        }
      }
    }
    console.log('')
  }

  // Summary section.
  const summary = result.summary
  console.log(`${BOLD}--- Summary ---${RESET}`)
  console.log(`  Servers scanned:       ${summary?.total_servers ?? result.servers.length}`)
  console.log(`  Tools analyzed:        ${summary?.total_tools_analyzed ?? result.servers.reduce((sum, s) => sum + s.tool_count, 0)}`)
  console.log(`  Known threats checked: ${summary?.known_threats_checked ?? knownThreatCount}`)
  if (clientDisplay) {
    console.log(`  Clients discovered:    ${clientDisplay}`)
  }
  if (summary?.scan_duration_ms !== undefined) {
    console.log(`  Scan duration:         ${(summary.scan_duration_ms / 1000).toFixed(2)}s`)
  }
  console.log('')

  // Recommendations section.
  console.log(`${BOLD}--- Recommendations ---${RESET}`)
  for (let i = 0; i < RECOMMENDATIONS.length; i++) {
    console.log(`  [${i + 1}] ${RECOMMENDATIONS[i]}`)
  }
  console.log('')

  // Grade explanation.
  const explanation = GRADE_EXPLANATIONS[result.overall_grade] || ''
  console.log(`Grade ${colorize(BOLD + result.overall_grade, gradeColor)} -- ${explanation}`)
  console.log('')
}
