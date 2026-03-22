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
import { printConsoleReport } from './reporters/console.js'
import { formatJSON, printJSONReport } from './reporters/json.js'
import { printSARIFReport } from './reporters/sarif.js'
import { runWatchMode } from './drift/index.js'
import type { ScanResult } from './types.js'

const SCANNER_VERSION = '0.1.0'

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

    // One-shot scan mode.
    const discoveryOpts = opts.config ? { configFile: opts.config } : {}
    const servers = discoverAllServers(discoveryOpts)

    const { servers: serverResults, findings } = analyzeAll(servers)
    const overallGrade = computeGrade(findings)

    const result: ScanResult = {
      scanned_at: new Date().toISOString(),
      overall_grade: overallGrade,
      finding_count: findings.length,
      servers: serverResults,
      findings,
      scanner_version: SCANNER_VERSION,
    }

    // Print format output.
    if (opts.format === 'json') {
      printJSONReport(result)
    } else if (opts.format === 'sarif') {
      printSARIFReport(result)
    } else {
      printConsoleReport(result)
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
        console.log('')
        console.log('  Track your security grade over time: https://app.agentdefenders.ai/signup')
      } else if (uploadedId) {
        console.log('')
        console.log(`  View full report: https://app.agentdefenders.ai/scanner/${uploadedId}`)
      } else {
        console.log('')
        console.log('  Failed to upload scan result. Check your API key and try again.')
      }
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
