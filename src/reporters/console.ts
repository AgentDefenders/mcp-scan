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
 *
 * Layout:
 *   1. Scan header (date, scope)
 *   2. Overall grade badge
 *   3. Per-server results (grade + analyzer checklist)
 *   4. Summary stats
 *   5. Recommendations
 *   6. Grade verdict
 *   7. CTA (shield dashboard)
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

  const gradeColor = GRADE_COLORS[result.overall_grade] || RESET

  // ── 1. Scan header ──────────────────────────────────────────────────
  const clientSuffix = clientDisplay ? ` (${clientDisplay})` : ''
  console.log(`  ${GRAY}${BOLD}MCP Security Scan${RESET}  ${GRAY}${new Date(result.scanned_at).toLocaleString()}${RESET}`)
  console.log(`  ${GRAY}Scanned ${WHITE}${result.servers.length}${GRAY} server${result.servers.length !== 1 ? 's' : ''} across ${WHITE}${clientNames.length}${GRAY} client${clientNames.length !== 1 ? 's' : ''}${clientSuffix}${RESET}`)
  console.log('')

  // ── 2. Overall grade ────────────────────────────────────────────────
  const findingText = result.finding_count === 0
    ? `${GREEN}${BOLD}0 findings${RESET}`
    : `${RED}${BOLD}${result.finding_count} finding${result.finding_count !== 1 ? 's' : ''}${RESET}`
  console.log(`  ${GRAY}Overall grade:${RESET} ${gradeColor}${BOLD}${result.overall_grade}${RESET}  ${findingText}`)
  console.log(`  ${GRAY}${horizontalLine(60)}${RESET}`)
  console.log('')

  if (result.servers.length === 0) {
    console.log(`  ${YELLOW}No MCP servers found in supported client configurations.${RESET}`)
    console.log('')
    return
  }

  // ── 3. Per-server results ───────────────────────────────────────────
  for (const server of result.servers) {
    const sg = GRADE_COLORS[server.grade] || RESET
    const originalServer = serverMap.get(server.server_name)

    const toolLabel = server.tool_count === 0
      ? 'config-only'
      : `${server.tool_count} tool${server.tool_count !== 1 ? 's' : ''}`

    const serverWithMeta = {
      ...server,
      command: originalServer?.command,
      args: originalServer?.args,
      transport: originalServer?.transport,
    }
    const cmdPath = formatCommandPath(serverWithMeta, 40)
    const transport = inferTransport(serverWithMeta)

    // Server header: grade + name on first line, command on second
    console.log(`  ${sg}${BOLD}${server.grade}${RESET}  ${WHITE}${BOLD}${server.server_name}${RESET}  ${GRAY}(${toolLabel})${RESET}  ${GRAY}[${transport}]${RESET}`)
    if (cmdPath) {
      console.log(`     ${GRAY}${cmdPath}${RESET}`)
    }

    if (server.findings.length === 0) {
      // Clean server: compact single-line pass indicators
      const passLine = ALL_ANALYZERS.map((a) => {
        if (a === 'known-threats') return `${GREEN}✓${RESET}${GRAY}threats${RESET}`
        const short = a.replace('tool-', '').replace('prompt-', '').replace('suspicious-', '')
        return `${GREEN}✓${RESET}${GRAY}${short}${RESET}`
      }).join('  ')
      console.log(`     ${passLine}`)
    } else {
      // Server with findings: show all analyzers
      const findingAnalyzers = new Set(server.findings.map((f) => f.analyzer))

      // Pass/fail for each analyzer on one line
      const statusLine = ALL_ANALYZERS.map((a) => {
        const hasFinding = findingAnalyzers.has(a)
        const short = a === 'known-threats' ? 'threats'
          : a.replace('tool-', '').replace('prompt-', '').replace('suspicious-', '')
        if (hasFinding) {
          return `${RED}✗${RESET}${GRAY}${short}${RESET}`
        }
        return `${GREEN}✓${RESET}${GRAY}${short}${RESET}`
      }).join('  ')
      console.log(`     ${statusLine}`)

      // Detail each finding
      for (const finding of server.findings) {
        const sc = SEVERITY_COLORS[finding.severity] || RESET
        const toolSuffix = finding.tool_name && finding.tool_name !== '*'
          ? `${WHITE} ${finding.tool_name}${RESET}` : ''
        console.log('')
        console.log(`     ${sc}${BOLD}${finding.severity.toUpperCase()}${RESET}  ${WHITE}${finding.analyzer}${RESET}${toolSuffix}`)
        console.log(`     ${GRAY}${finding.description}${RESET}`)
        if (finding.evidence && finding.evidence.length > 0) {
          const snippet = finding.evidence.slice(0, 100)
          console.log(`     ${GRAY}${ITALIC}${snippet}${finding.evidence.length > 100 ? '...' : ''}${RESET}`)
        }
        if (finding.remediation) {
          console.log(`     ${BRIGHT_CYAN}fix:${RESET} ${CYAN}${finding.remediation}${RESET}`)
        }
      }
    }
    console.log('')
  }

  // ── 4. Summary ──────────────────────────────────────────────────────
  const summary = result.summary
  const serverCount = summary?.total_servers ?? result.servers.length
  const toolsAnalyzed = summary?.total_tools_analyzed ?? result.servers.reduce((sum, s) => sum + s.tool_count, 0)
  const threatsChecked = summary?.known_threats_checked ?? knownThreatCount
  const duration = summary?.scan_duration_ms !== undefined ? `${(summary.scan_duration_ms / 1000).toFixed(2)}s` : null

  console.log(`  ${GRAY}${horizontalLine(60)}${RESET}`)
  const durationStr = duration ? `  ${GRAY}in ${WHITE}${duration}${GRAY}${RESET}` : ''
  console.log(`  ${WHITE}${BOLD}${serverCount}${RESET}${GRAY} servers  ${WHITE}${BOLD}${toolsAnalyzed}${RESET}${GRAY} tools  ${WHITE}${BOLD}${threatsChecked}${RESET}${GRAY} threats checked${durationStr}${RESET}`)
  if (clientDisplay) {
    console.log(`  ${GRAY}Clients: ${WHITE}${clientDisplay}${RESET}`)
  }
  console.log('')

  // ── 5. Recommendations ──────────────────────────────────────────────
  console.log(`  ${GRAY}${BOLD}Recommendations${RESET}`)
  for (const rec of RECOMMENDATIONS) {
    console.log(`  ${GRAY}  ${BRIGHT_GREEN}◆${RESET} ${GRAY}${rec}${RESET}`)
  }
  console.log('')

  // ── 6. Grade verdict ────────────────────────────────────────────────
  const explanation = GRADE_EXPLANATIONS[result.overall_grade] || ''
  console.log(`  ${gradeColor}${BOLD}Grade ${result.overall_grade}${RESET} ${GRAY}-- ${explanation}${RESET}`)
  console.log('')

  // ── 7. CTA ──────────────────────────────────────────────────────────
  console.log(`  ${GRAY}${horizontalLine(60)}${RESET}`)
  console.log(`  ${BRIGHT_GREEN}${BOLD}Track your results on the Shield dashboard:${RESET}`)
  console.log(`  ${GRAY}1.${RESET} Sign up:       ${BRIGHT_CYAN}${UNDERLINE}https://app.agentdefenders.ai${RESET}`)
  console.log(`  ${GRAY}2.${RESET} Get API key:   ${GRAY}Settings > API Keys${RESET}`)
  console.log(`  ${GRAY}3.${RESET} Re-run:        ${WHITE}npx @agentdefenders/mcp-scan --api-key shld_xxx${RESET}`)
  console.log('')
}
