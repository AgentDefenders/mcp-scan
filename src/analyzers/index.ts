import type { Finding, Grade, MCPServer, ServerScanResult } from '../types.js'
import { analyzeToolPoisoning } from './tool-poisoning.js'
import { analyzePromptInjection } from './prompt-injection.js'
import { analyzeShadowing } from './shadowing.js'
import { analyzeSuspiciousEnv } from './suspicious-env.js'
import { analyzeKnownThreats } from './known-threats.js'

/**
 * Compute the security grade from a list of findings.
 * A: 0 findings
 * B: low-severity findings only
 * C: medium-severity findings
 * D: high-severity findings
 * F: critical-severity findings
 */
export function computeGrade(findings: Finding[]): Grade {
  if (findings.length === 0) return 'A'
  const severities = new Set(findings.map((f) => f.severity))
  if (severities.has('critical')) return 'F'
  if (severities.has('high')) return 'D'
  if (severities.has('medium')) return 'C'
  return 'B'
}

/**
 * Run all analyzers against a single MCP server and return per-server results.
 */
export function analyzeServer(server: MCPServer): ServerScanResult {
  const findings: Finding[] = [
    ...analyzeToolPoisoning(server),
    ...analyzePromptInjection(server),
    ...analyzeShadowing(server),
    ...analyzeSuspiciousEnv(server),
    ...analyzeKnownThreats(server),
  ]
  return {
    server_name: server.name,
    grade: computeGrade(findings),
    tool_count: server.tools?.length ?? 0,
    findings,
  }
}

/**
 * Run all analyzers against all discovered servers.
 */
export function analyzeAll(servers: MCPServer[]): { servers: ServerScanResult[]; findings: Finding[] } {
  const serverResults = servers.map(analyzeServer)
  const allFindings = serverResults.flatMap((s) => s.findings)
  return { servers: serverResults, findings: allFindings }
}
