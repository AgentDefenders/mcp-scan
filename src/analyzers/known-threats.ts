import type { Finding, MCPServer, Severity } from '../types.js'
import threats from '../data/known-threats.json'

/** Structure of a known threat entry from the threat database. */
interface KnownThreat {
  /** Unique identifier for this threat. */
  id: string
  /** Human-readable name of the threat. */
  name: string
  /** Pattern matching rules for server detection. */
  match_patterns: {
    commands?: string[]
    server_names?: string[]
    args_contains?: string[]
  }
  /** Severity of this threat. */
  severity: string
  /** Description of the threat. */
  description: string
  /** Optional CVE reference. */
  cve?: string
  /** Optional reference URL. */
  reference?: string
  /** Concrete remediation steps. */
  remediation: string
  /** Date this threat was added to the database. */
  added_at: string
}

const knownThreats: KnownThreat[] = threats as KnownThreat[]

/**
 * Analyze an MCP server against the known vulnerability database.
 * Checks server command, args, and name against known threat patterns.
 * Returns findings for any matching threat entries.
 */
export function analyzeKnownThreats(server: MCPServer): Finding[] {
  const findings: Finding[] = []

  for (const threat of knownThreats) {
    let matched = false
    let matchField = ''
    let matchEvidence = ''

    const hasCommandPatterns = threat.match_patterns.commands && threat.match_patterns.commands.length > 0
    const hasArgsPatterns = threat.match_patterns.args_contains && threat.match_patterns.args_contains.length > 0
    const hasNamePatterns = threat.match_patterns.server_names && threat.match_patterns.server_names.length > 0

    // Check server name against known malicious server names (case-insensitive).
    if (hasNamePatterns) {
      const serverNameLower = server.name.toLowerCase()
      for (const pattern of threat.match_patterns.server_names!) {
        if (serverNameLower === pattern.toLowerCase()) {
          matched = true
          matchField = 'name'
          matchEvidence = `Server name "${server.name}" matches known threat pattern "${pattern}"`
          break
        }
      }
    }

    // When both commands AND args_contains are specified, require BOTH to match
    // (e.g., "npx" + "hack-mcp" = suspicious; "npx" alone is not).
    if (!matched && hasCommandPatterns && hasArgsPatterns) {
      let commandMatches = false
      let argsMatch = false
      let cmdPattern = ''
      let argPattern = ''

      if (server.command) {
        const commandLower = server.command.toLowerCase()
        for (const pattern of threat.match_patterns.commands!) {
          if (commandLower.includes(pattern.toLowerCase())) {
            commandMatches = true
            cmdPattern = pattern
            break
          }
        }
      }

      if (commandMatches && server.args) {
        const argsJoined = server.args.join(' ')
        for (const pattern of threat.match_patterns.args_contains!) {
          if (argsJoined.includes(pattern)) {
            argsMatch = true
            argPattern = pattern
            break
          }
        }
      }

      if (commandMatches && argsMatch) {
        matched = true
        matchField = 'command+args'
        matchEvidence = `Command "${server.command}" with args containing "${argPattern}" matches known threat "${cmdPattern}+${argPattern}"`
      }
    }

    // Command-only match (no args_contains required).
    if (!matched && hasCommandPatterns && !hasArgsPatterns && server.command) {
      const commandLower = server.command.toLowerCase()
      for (const pattern of threat.match_patterns.commands!) {
        if (commandLower.includes(pattern.toLowerCase())) {
          matched = true
          matchField = 'command'
          matchEvidence = `Command "${server.command}" matches known threat pattern "${pattern}"`
          break
        }
      }
    }

    // Args-only match (no commands required).
    if (!matched && hasArgsPatterns && !hasCommandPatterns && server.args) {
      const argsJoined = server.args.join(' ')
      for (const pattern of threat.match_patterns.args_contains!) {
        if (argsJoined.includes(pattern)) {
          matched = true
          matchField = 'args'
          matchEvidence = `Server args contain known threat pattern "${pattern}"`
          break
        }
      }
    }

    if (matched) {
      const severity = threat.severity as Severity
      const cveRef = threat.cve ? ` (${threat.cve})` : ''
      const refLink = threat.reference ? ` Reference: ${threat.reference}` : ''

      findings.push({
        analyzer: 'known-threats',
        severity,
        server_name: server.name,
        tool_name: '*',
        description: `${threat.name}${cveRef}: ${threat.description}`,
        field: matchField,
        evidence: matchEvidence,
        remediation: `${threat.remediation}${refLink}`,
      })
    }
  }

  return findings
}

/**
 * Returns the total number of known threats in the database.
 * Useful for scan summary statistics.
 */
export function getKnownThreatCount(): number {
  return knownThreats.length
}
