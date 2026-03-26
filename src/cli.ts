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
import { printConsoleReport } from './reporters/console.js'
import { formatJSON, printJSONReport } from './reporters/json.js'
import { printSARIFReport } from './reporters/sarif.js'
import { runWatchMode } from './drift/index.js'
import type { ScanResult, ScanSummary } from './types.js'

const SCANNER_VERSION = '0.2.0'

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
  .option('--badge', 'Print a shields.io badge URL based on scan grade')
  .action(async (opts) => {
    // Drift detection mode.
    if (opts.watch) {
      await runWatchMode({
        intervalSeconds: parseInt(opts.interval, 10) || 300,
        apiKey: opts.apiKey || process.env.SHIELD_API_KEY,
        apiBase: opts.apiBase,
        baselineFile: path.join(os.homedir(), '.config', 'sysmond', 'mcp_baselines.json'),
      })
      return
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
    if (opts.format !== 'json' && opts.format !== 'sarif' && !opts.quiet) {
      if (!apiKey) {
        console.log('Track your security posture: https://app.agentdefenders.ai/scanner')
      } else if (uploadedId) {
        console.log(`View full report: https://app.agentdefenders.ai/scanner/${uploadedId}`)
      } else {
        console.log('Failed to upload scan result. Check your API key and try again.')
      }
      console.log('')
    }

    // Exit code enforcement.
    if (opts.failOn) {
      const severity = opts.failOn as string
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
