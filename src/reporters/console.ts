import type { MCPServer, ScanResult, ServerScanResult } from '../types.js'
import { getKnownThreatCount } from '../analyzers/known-threats.js'

// ---------------------------------------------------------------------------
// ANSI escape sequences
// ---------------------------------------------------------------------------
const RESET = '\x1b[0m'
const BOLD = '\x1b[1m'
const DIM = '\x1b[2m'
const ITALIC = '\x1b[3m'
const UNDERLINE = '\x1b[4m'

// Colors
const RED = '\x1b[31m'
const GREEN = '\x1b[32m'
const YELLOW = '\x1b[33m'
const CYAN = '\x1b[36m'
const WHITE = '\x1b[97m'
const BRIGHT_GREEN = '\x1b[92m'
const BRIGHT_CYAN = '\x1b[96m'
const GRAY = '\x1b[90m'

// Background
const BG_RED = '\x1b[41m'
const BG_GREEN = '\x1b[42m'
const BG_YELLOW = '\x1b[43m'

const GRADE_COLORS: Record<string, string> = {
  A: GREEN,
  B: GREEN,
  C: YELLOW,
  D: YELLOW,
  F: RED,
}
const GRADE_BG: Record<string, string> = {
  A: BG_GREEN,
  B: BG_GREEN,
  C: BG_YELLOW,
  D: BG_YELLOW,
  F: BG_RED,
}
const SEVERITY_COLORS: Record<string, string> = {
  critical: RED,
  high: YELLOW,
  medium: CYAN,
  low: GRAY,
}

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

// ---------------------------------------------------------------------------
// Box-drawing helpers (Claude Code style)
// ---------------------------------------------------------------------------
const BOX = {
  topLeft: '\u250c',     // left top corner
  topRight: '\u2510',    // right top corner
  bottomLeft: '\u2514',  // left bottom corner
  bottomRight: '\u2518', // right bottom corner
  horizontal: '\u2500',  // horizontal line
  vertical: '\u2502',    // vertical line
  teeRight: '\u251c',    // T right
  teeLeft: '\u2524',     // T left
}

function horizontalLine(width: number): string {
  return BOX.horizontal.repeat(width)
}

function boxTop(width: number): string {
  return `${GRAY}${BOX.topLeft}${horizontalLine(width)}${BOX.topRight}${RESET}`
}

function boxBottom(width: number): string {
  return `${GRAY}${BOX.bottomLeft}${horizontalLine(width)}${BOX.bottomRight}${RESET}`
}

function boxMid(width: number): string {
  return `${GRAY}${BOX.teeRight}${horizontalLine(width)}${BOX.teeLeft}${RESET}`
}

function boxLine(content: string, width: number): string {
  // Strip ANSI to calculate visible length for padding
  const visible = content.replace(/\x1b\[[0-9;]*m/g, '')
  const pad = Math.max(0, width - visible.length)
  return `${GRAY}${BOX.vertical}${RESET} ${content}${' '.repeat(pad)}${GRAY}${BOX.vertical}${RESET}`
}

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

/**
 * Redact values in args that look like secrets.
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

// ---------------------------------------------------------------------------
// Banner
// ---------------------------------------------------------------------------

/**
 * Print the AgentDefenders banner.
 *
 * Design: nested hexagonal shield matching the sentinel mark SVG logo.
 * The SVG has 3 concentric hexagonal layers with a green diamond (◆)
 * at the center and a scan line. This ASCII version captures the
 * layered shield shape with rounded box border (outer layer), inner
 * shield chevrons (middle layer), and the green diamond (core).
 *
 *     ╭───╮       AgentDefenders mcp-scan v0.x.x
 *    │ ╱╲ │      MCP supply chain security scanner
 *    │ ╲◆╱ │      Detects poisoning, injection, shadowing, known threats
 *    ╰─╲▾╱─╯      All analysis runs locally. No data leaves your machine.
 */
export function printBanner(version: string): void {
  const c = BRIGHT_CYAN
  const d = GRAY
  const r = RESET

  console.log('')
  console.log(`    ${d}╭───╮${r}       ${WHITE}${BOLD}AgentDefenders${r} ${c}mcp-scan${r} ${d}v${version}${r}`)
  console.log(`    ${d}│${WHITE} ╱╲ ${d}│${r}      ${d}MCP supply chain security scanner${r}`)
  console.log(`    ${d}│${WHITE} ╲${BRIGHT_GREEN}${BOLD}◆${r}${WHITE}╱ ${d}│${r}      ${d}Detects poisoning, injection, shadowing, known threats${r}`)
  console.log(`    ${d}╰─${WHITE}╲${BRIGHT_GREEN}▾${WHITE}╱${d}─╯${r}      ${d}All analysis runs locally. No data leaves your machine.${r}`)
  console.log('')
}

// ---------------------------------------------------------------------------
// Console report
// ---------------------------------------------------------------------------

/**
 * Print a human-readable scan report to stdout.
 * Uses box-drawing characters and ANSI colors for a professional terminal UI.
 */
export function printConsoleReport(result: ScanResult, servers?: MCPServer[]): void {
  const knownThreatCount = getKnownThreatCount()
  const W = 72 // box width (inner)

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

  // --- Header box ---
  console.log(boxTop(W))
  console.log(boxLine(`${WHITE}${BOLD}MCP Security Scan${RESET}  ${GRAY}${new Date(result.scanned_at).toLocaleString()}${RESET}`, W))
  const clientSuffix = clientDisplay ? ` ${GRAY}(${clientDisplay})${RESET}` : ''
  console.log(boxLine(`${DIM}Scanned ${result.servers.length} server${result.servers.length !== 1 ? 's' : ''} across ${clientNames.length} client${clientNames.length !== 1 ? 's' : ''}${clientSuffix}${RESET}`, W))
  console.log(boxBottom(W))
  console.log('')

  // --- Overall grade ---
  const gradeColor = GRADE_COLORS[result.overall_grade] || RESET
  const gradeBg = GRADE_BG[result.overall_grade] || ''
  const findingText = result.finding_count === 0
    ? `${GREEN}0 findings${RESET}`
    : `${RED}${result.finding_count} finding${result.finding_count !== 1 ? 's' : ''}${RESET}`
  console.log(`  ${BOLD}Overall Grade:${RESET} ${gradeBg}${WHITE}${BOLD} ${result.overall_grade} ${RESET}  ${findingText}`)
  console.log('')

  if (result.servers.length === 0) {
    console.log(`  ${YELLOW}No MCP servers found in supported client configurations.${RESET}`)
    console.log('')
    return
  }

  // --- Per-server results ---
  for (const server of result.servers) {
    const sg = GRADE_COLORS[server.grade] || RESET
    const originalServer = serverMap.get(server.server_name)

    const toolLabel = server.tool_count === 0
      ? `${GRAY}config-only${RESET}`
      : `${server.tool_count} tool${server.tool_count !== 1 ? 's' : ''}`

    const serverWithMeta = {
      ...server,
      command: originalServer?.command,
      args: originalServer?.args,
      transport: originalServer?.transport,
    }
    const cmdPath = formatCommandPath(serverWithMeta, 45)
    const transport = inferTransport(serverWithMeta)
    const cmdDisplay = cmdPath ? `  ${GRAY}${cmdPath}${RESET}` : ''

    // Server header line: grade badge + name + metadata
    console.log(`  ${sg}${BOLD}${server.grade}${RESET}  ${WHITE}${BOLD}${server.server_name}${RESET}  ${GRAY}(${toolLabel})${cmdDisplay}  [${transport}]${RESET}`)

    if (server.findings.length === 0) {
      // Show pass checklist with checkmarks
      for (const analyzer of ALL_ANALYZERS) {
        const suffix = analyzer === 'known-threats'
          ? ` ${GRAY}(${knownThreatCount} threats checked)${RESET}`
          : ''
        console.log(`     ${GREEN}${BOLD}✓${RESET} ${DIM}${analyzer}${RESET}${suffix}`)
      }
    } else {
      // Show passing analyzers first
      const findingAnalyzers = new Set(server.findings.map((f) => f.analyzer))
      for (const analyzer of ALL_ANALYZERS) {
        if (!findingAnalyzers.has(analyzer)) {
          const suffix = analyzer === 'known-threats'
            ? ` ${GRAY}(${knownThreatCount} threats checked)${RESET}`
            : ''
          console.log(`     ${GREEN}${BOLD}✓${RESET} ${DIM}${analyzer}${RESET}${suffix}`)
        }
      }

      // Show findings with severity badges
      for (const finding of server.findings) {
        const sc = SEVERITY_COLORS[finding.severity] || RESET
        const toolSuffix = finding.tool_name && finding.tool_name !== '*' ? `  ${WHITE}${finding.tool_name}${RESET}` : ''
        const sevLabel = finding.severity.toUpperCase().padEnd(8)
        console.log(`     ${sc}${BOLD}✗${RESET} ${sc}${sevLabel}${RESET} ${finding.analyzer}${toolSuffix}`)
        console.log(`       ${GRAY}${finding.description}${RESET}`)
        if (finding.evidence && finding.evidence.length > 0) {
          const evidenceSnippet = finding.evidence.slice(0, 100)
          console.log(`       ${GRAY}${ITALIC}evidence: ${evidenceSnippet}${finding.evidence.length > 100 ? '...' : ''}${RESET}`)
        }
        if (finding.remediation) {
          console.log(`       ${CYAN}fix: ${finding.remediation}${RESET}`)
        }
      }
    }
    console.log('')
  }

  // --- Summary box ---
  const summary = result.summary
  const toolsAnalyzed = summary?.total_tools_analyzed ?? result.servers.reduce((sum, s) => sum + s.tool_count, 0)
  const duration = summary?.scan_duration_ms !== undefined ? `${(summary.scan_duration_ms / 1000).toFixed(2)}s` : '—'

  console.log(boxTop(W))
  console.log(boxLine(`${WHITE}${BOLD}Summary${RESET}`, W))
  console.log(boxMid(W))
  console.log(boxLine(`  Servers scanned       ${WHITE}${summary?.total_servers ?? result.servers.length}${RESET}`, W))
  console.log(boxLine(`  Tools analyzed        ${WHITE}${toolsAnalyzed}${RESET}`, W))
  console.log(boxLine(`  Known threats checked ${WHITE}${summary?.known_threats_checked ?? knownThreatCount}${RESET}`, W))
  if (clientDisplay) {
    console.log(boxLine(`  Clients discovered    ${WHITE}${clientDisplay}${RESET}`, W))
  }
  console.log(boxLine(`  Scan duration         ${WHITE}${duration}${RESET}`, W))
  console.log(boxBottom(W))
  console.log('')

  // --- Recommendations ---
  console.log(`  ${GRAY}${BOLD}Recommendations${RESET}`)
  for (let i = 0; i < RECOMMENDATIONS.length; i++) {
    console.log(`  ${GRAY}${i + 1}. ${RECOMMENDATIONS[i]}${RESET}`)
  }
  console.log('')

  // --- Grade explanation ---
  const explanation = GRADE_EXPLANATIONS[result.overall_grade] || ''
  console.log(`  ${gradeColor}${BOLD}Grade ${result.overall_grade}${RESET} ${GRAY}${explanation}${RESET}`)
  console.log('')
}
