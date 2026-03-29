#!/usr/bin/env node
/**
 * mcp-scan CLI entry point.
 * Usage: mcp-scan [options]
 */
import { Command } from 'commander'
import * as path from 'path'
import * as os from 'os'
import { discoverAllServers } from './discovery/index.js'
import { analyzeAll, computeGrade } from './analyzers/index.js'
import { getKnownThreatCount } from './analyzers/known-threats.js'
import { printBanner, printConsoleReport } from './reporters/console.js'
import { formatJSON, printJSONReport } from './reporters/json.js'
import { printSARIFReport } from './reporters/sarif.js'
import { printGitHubAnnotations, writeStepSummary } from './reporters/github.js'
import { runWatchMode } from './drift/index.js'
import type { ScanResult, ScanSummary } from './types.js'

const SCANNER_VERSION = '0.2.2-alpha'

/** Badge color mapping by grade. */
const BADGE_COLORS: Record<string, string> = {
  A: 'brightgreen',
  B: 'brightgreen',
  C: 'yellow',
  D: 'orange',
  F: 'red',
}

const program = new Command()

program
  .name('mcp-scan')
  .description('MCP supply chain scanner: detect tool poisoning, prompt injection, and shadowing attacks')
  .version(SCANNER_VERSION)
  .option('--config <path>', 'Path to a specific MCP config file (skips auto-discovery)')
  .option('--format <format>', 'Output format: console, json, or sarif', 'console')
  .option('--fail-on <severity>', 'Exit with code 1 if findings at or above this severity are found')
  .option('--api-key <key>', 'Shield API key (shld_xxx) for uploading results to the dashboard')
  .option('--api-base <url>', 'Shield API base URL (default: https://api.agentdefenders.ai)')
  .option('--watch', 'Run in drift detection mode (polls at --interval seconds)')
  .option('--interval <seconds>', 'Polling interval for --watch mode', '300')
  .option('--quiet', 'Suppress CTA output (for CI environments)')
  .option('--ci', 'CI mode: GitHub Actions annotations, step summary, no interactive prompts')
  .option('--badge', 'Print a shields.io badge URL based on scan grade')
  .option('--protect', 'After scanning, deploy Supply Shield canary tokens to protect your CI pipeline')
  .option('--protect-package <package>', 'Supply Shield alarm package (generic, oss-python, ai-ml-pipeline, node-backend)', 'generic')
  .option('--protect-email <email>', 'Email for Supply Shield trip alerts (free tier, no signup)')
  .action(async (opts) => {
    // Drift detection mode.
    if (opts.watch) {
      await runWatchMode({
        intervalSeconds: parseInt(opts.interval, 10) || 300,
        apiKey: opts.apiKey || process.env.SHIELD_API_KEY,
        apiBase: opts.apiBase,
        baselineFile: path.join(os.homedir(), '.config', 'mcp-scan', 'baselines.json'),
      })
      return
    }

    // CI mode implies quiet (no interactive prompts or CTA).
    const isCI = !!opts.ci
    const isQuiet = !!opts.quiet || isCI

    // Print banner in console mode when not quiet.
    if (opts.format !== 'json' && opts.format !== 'sarif' && !isQuiet) {
      printBanner(SCANNER_VERSION)
    }

    // Capture start time for duration measurement.
    const scanStartMs = Date.now()

    // One-shot scan mode.
    const discoveryOpts = opts.config ? { configFile: opts.config } : {}
    const servers = discoverAllServers(discoveryOpts)

    const { servers: serverResults, findings } = analyzeAll(servers)
    const overallGrade = computeGrade(findings)

    const scanDurationMs = Date.now() - scanStartMs

    // Derive unique client names from discovered servers.
    const clientsSet = new Set<string>()
    for (const s of servers) {
      if (s.source_client) {
        clientsSet.add(s.source_client)
      }
    }
    const clientsDiscovered = Array.from(clientsSet)

    // Build scan summary.
    const serversWithFindings = serverResults.filter((s) => s.findings.length > 0).length
    const totalToolsAnalyzed = serverResults.reduce((sum, s) => sum + s.tool_count, 0)

    const summary: ScanSummary = {
      total_servers: serverResults.length,
      total_tools_analyzed: totalToolsAnalyzed,
      servers_with_findings: serversWithFindings,
      servers_clean: serverResults.length - serversWithFindings,
      clients_discovered: clientsDiscovered,
      known_threats_checked: getKnownThreatCount(),
      scan_duration_ms: scanDurationMs,
    }

    const result: ScanResult = {
      scanned_at: new Date().toISOString(),
      overall_grade: overallGrade,
      finding_count: findings.length,
      servers: serverResults,
      findings,
      scanner_version: SCANNER_VERSION,
      summary,
    }

    // Print format output.
    if (opts.format === 'json') {
      printJSONReport(result)
    } else if (opts.format === 'sarif') {
      printSARIFReport(result)
    } else {
      printConsoleReport(result, servers)
    }

    // CI mode: emit GitHub Actions annotations and step summary.
    if (isCI) {
      printGitHubAnnotations(result)
      writeStepSummary(result)
    }

    // Print badge URL if --badge flag is set.
    if (opts.badge) {
      const badgeColor = BADGE_COLORS[overallGrade] || 'lightgrey'
      console.log('')
      console.log(`https://img.shields.io/badge/MCP%20Security-Grade%20${overallGrade}-${badgeColor}`)
    }

    // Upload result if API key is provided via flag or SHIELD_API_KEY env var.
    const apiKey = opts.apiKey || process.env.SHIELD_API_KEY
    let uploadedId: string | null = null
    if (apiKey) {
      uploadedId = await uploadScanResult(result, apiKey, opts.apiBase || 'https://api.agentdefenders.ai')
    }

    // Print CTA only in console format and when not quiet.
    if (opts.format !== 'json' && opts.format !== 'sarif' && !isQuiet) {
      const GRAY = '\x1b[90m'
      const CYAN = '\x1b[36m'
      const BCYAN = '\x1b[96m'
      const GREEN = '\x1b[92m'
      const WHITE = '\x1b[97m'
      const BOLD = '\x1b[1m'
      const UL = '\x1b[4m'
      const RST = '\x1b[0m'
      const HR = '\x1b[90m' + '\u2500'.repeat(60) + RST

      if (!apiKey) {
        console.log(`  ${HR}`)
        console.log(`  ${GREEN}${BOLD}Track your results on the Shield dashboard:${RST}`)
        console.log(`  ${GRAY}1.${RST} Sign up:       ${BCYAN}${UL}https://app.agentdefenders.ai${RST}`)
        console.log(`  ${GRAY}2.${RST} Get API key:   ${GRAY}Settings > API Keys${RST}`)
        console.log(`  ${GRAY}3.${RST} Re-run:        ${WHITE}npx @agentdefenders/mcp-scan --api-key shld_xxx${RST}`)
        console.log('')
      } else if (uploadedId) {
        console.log(`  ${HR}`)
        console.log(`  ${GREEN}${BOLD}Scan uploaded.${RST} ${GRAY}View full report:${RST}`)
        console.log(`  ${BCYAN}${UL}https://app.agentdefenders.ai/scanner/${uploadedId}${RST}`)
        console.log('')
      } else {
        console.log(`  ${HR}`)
        console.log(`  ${GRAY}Upload failed. Check your API key and try again.${RST}`)
        console.log('')
      }
    }

    // Supply Shield: deploy canary tokens after scan if --protect is set.
    if (opts.protect) {
      const protectEmail = opts.protectEmail || process.env.SUPPLY_SHIELD_EMAIL
      const protectKey = apiKey // reuse the same API key for Supply Shield
      const protectPackage = opts.protectPackage || 'generic'
      const protectApiBase = opts.apiBase || 'https://api.agentdefenders.ai'

      if (!protectEmail && !protectKey) {
        const YELLOW = '\x1b[33m'
        const RST = '\x1b[0m'
        console.log(`\n  ${YELLOW}--protect requires --protect-email <email> or --api-key <key>${RST}`)
        console.log(`  ${YELLOW}Example: npx @agentdefenders/mcp-scan --protect --protect-email you@example.com${RST}\n`)
      } else {
        const protectResult = await deploySupplyShield({
          email: protectEmail,
          apiKey: protectKey,
          package: protectPackage,
          apiBase: protectApiBase,
        })
        if (protectResult) {
          const GREEN = '\x1b[92m'
          const BOLD = '\x1b[1m'
          const RST = '\x1b[0m'
          const GRAY = '\x1b[90m'
          console.log(`\n  ${GREEN}${BOLD}Supply Shield activated.${RST}`)
          console.log(`  ${GRAY}${protectResult.tokens.length} canary tokens deployed (${protectPackage} package).${RST}`)
          console.log(`  ${GRAY}Expires: ${protectResult.expires_at || 'never (paid tier)'}${RST}`)
          console.log(`  ${GRAY}Add this to your CI workflow for continuous protection:${RST}`)
          console.log(`\n  ${BOLD}  - uses: AgentDefenders/supply-shield@v1${RST}`)
          console.log(`  ${BOLD}    with:${RST}`)
          if (protectEmail) {
            console.log(`  ${BOLD}      email: ${protectEmail}${RST}`)
          } else {
            console.log(`  ${BOLD}      api-key: \${{ secrets.SHIELD_KEY }}${RST}`)
            console.log(`  ${BOLD}      package: ${protectPackage}${RST}`)
          }
          console.log('')
        }
      }
    }

    // Exit code enforcement. CI mode defaults to --fail-on high.
    const failOnSeverity = opts.failOn || (isCI ? 'high' : undefined)
    if (failOnSeverity) {
      const severity = failOnSeverity as string
      const severityOrder = ['low', 'medium', 'high', 'critical']
      const threshold = severityOrder.indexOf(severity)
      if (threshold !== -1) {
        const hasFailingFindings = findings.some((f) => severityOrder.indexOf(f.severity) >= threshold)
        if (hasFailingFindings) {
          process.exit(1)
        }
      }
    }
  })

program.parse()

/**
 * Upload scan result to the Shield API dashboard.
 * Returns the scan id on success, or null on failure.
 */
async function uploadScanResult(result: ScanResult, apiKey: string, apiBase: string): Promise<string | null> {
  try {
    const res = await fetch(`${apiBase}/api/v1/scans`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        scan_type: 'mcp_config',
        overall_grade: result.overall_grade,
        finding_count: result.finding_count,
        findings: result.findings,
        scanner_version: result.scanner_version,
        raw_result: result,
      }),
    })
    if (!res.ok) {
      console.error(`Failed to upload scan result: HTTP ${res.status}`)
      return null
    } else {
      const body = await res.json() as { id?: string }
      if (process.env.MCP_SCAN_DEBUG) {
        console.error(`Scan result uploaded: ${body.id}`)
      }
      return body.id ?? null
    }
  } catch (err) {
    console.error(`Failed to upload scan result: ${err instanceof Error ? err.message : String(err)}`)
    return null
  }
}

/**
 * Deploy Supply Shield canary tokens via the provision endpoint.
 * Returns the provision response on success, or null on failure.
 */
interface SupplyShieldToken {
  type: string
  key: string
  value: string
  canary_id: string
}

interface SupplyShieldResult {
  tokens: SupplyShieldToken[]
  expires_at: string | null
}

async function deploySupplyShield(opts: {
  email?: string
  apiKey?: string
  package: string
  apiBase: string
}): Promise<SupplyShieldResult | null> {
  try {
    // Determine repo from git if available (no shell, safe from injection).
    let repo = 'unknown/local'
    try {
      const { execFileSync } = await import('child_process')
      const remoteUrl = execFileSync('git', ['remote', 'get-url', 'origin'], {
        encoding: 'utf-8',
        stdio: ['pipe', 'pipe', 'pipe'],
      }).trim()
      const match = remoteUrl.match(/[:/]([^/]+\/[^/.]+?)(?:\.git)?$/)
      if (match) repo = match[1]
    } catch {
      // Not in a git repo or no remote. Use hostname as identifier.
      repo = `local/${os.hostname()}`
    }

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'User-Agent': `mcp-scan/${SCANNER_VERSION}`,
    }
    if (opts.apiKey) {
      headers['Authorization'] = `Bearer ${opts.apiKey}`
    }

    const body = {
      email: opts.email,
      package: opts.package,
      repo,
    }

    const res = await fetch(`${opts.apiBase}/v1/supply-shield/provision`, {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(30_000),
    })

    if (!res.ok) {
      const text = await res.text().catch(() => '')
      console.error(`Supply Shield provision failed: HTTP ${res.status} ${text}`)
      return null
    }

    return await res.json() as SupplyShieldResult
  } catch (err) {
    console.error(`Supply Shield provision failed: ${err instanceof Error ? err.message : String(err)}`)
    return null
  }
}
