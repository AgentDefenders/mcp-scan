import type { ScanResult, Finding, Severity } from '../types.js'

/** Maps mcp-scan severity to SARIF result level. */
function toSARIFLevel(severity: Severity): 'error' | 'warning' | 'note' {
  if (severity === 'critical' || severity === 'high') return 'error'
  if (severity === 'medium') return 'warning'
  return 'note'
}

/** SARIF rule entry derived from a unique analyzer name. */
interface SARIFRule {
  id: string
  name: string
  shortDescription: { text: string }
  helpUri: string
}

/** Build the deduplicated rule list from findings. */
function buildRules(findings: Finding[]): SARIFRule[] {
  const seen = new Set<string>()
  const rules: SARIFRule[] = []
  for (const f of findings) {
    if (!seen.has(f.analyzer)) {
      seen.add(f.analyzer)
      rules.push({
        id: f.analyzer,
        name: f.analyzer
          .split('-')
          .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
          .join(''),
        shortDescription: { text: `MCP ${f.analyzer} vulnerability` },
        helpUri: `https://agentdefenders.ai/docs/analyzers/${f.analyzer}`,
      })
    }
  }
  return rules
}

/**
 * Format a scan result as a SARIF 2.1.0 document.
 * Returns a JSON string suitable for writing to a .sarif file.
 */
export function formatSARIF(result: ScanResult): string {
  const rules = buildRules(result.findings)

  const results = result.findings.map((f) => ({
    ruleId: f.analyzer,
    level: toSARIFLevel(f.severity),
    message: {
      text: `${f.description} [server: ${f.server_name}, tool: ${f.tool_name}, field: ${f.field}, evidence: ${f.evidence}]`,
    },
    locations: [
      {
        physicalLocation: {
          artifactLocation: {
            uri: `mcp-config/${f.server_name}`,
            uriBaseId: '%SRCROOT%',
          },
          region: { startLine: 1 },
        },
        logicalLocations: [
          {
            name: f.tool_name,
            kind: 'member',
            fullyQualifiedName: `${f.server_name}/${f.tool_name}`,
          },
        ],
      },
    ],
  }))

  const sarif = {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'mcp-scan',
            version: result.scanner_version,
            informationUri: 'https://agentdefenders.ai',
            rules,
          },
        },
        results,
        invocations: [
          {
            executionSuccessful: true,
            endTimeUtc: result.scanned_at,
          },
        ],
      },
    ],
  }

  return JSON.stringify(sarif, null, 2)
}

/** Print SARIF output to stdout. */
export function printSARIFReport(result: ScanResult): void {
  console.log(formatSARIF(result))
}
