import type { Finding, MCPServer } from '../types.js'

/** Remediation guidance for tool-poisoning findings. */
const TOOL_POISONING_REMEDIATION =
  'Review the tool description for hidden instructions. Compare against the official MCP server documentation. If the description was modified, reinstall the MCP server from the original source.'

/**
 * Unicode control characters and invisible characters used to hide instructions.
 * These patterns are commonly used in tool poisoning attacks to embed hidden
 * instructions that are visible to the LLM but not to human reviewers.
 */
const UNICODE_HIDDEN_PATTERNS: Array<{ pattern: RegExp; description: string }> = [
  {
    pattern: /[\u200B-\u200F\u2028-\u202F\u2060-\u206F\uFEFF]/,
    description: 'Zero-width or invisible Unicode characters in tool description',
  },
  {
    pattern: /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/,
    description: 'Control characters in tool description',
  },
  {
    pattern: /<[^>]+>/,
    description: 'HTML tags in tool description (may contain hidden instructions)',
  },
  {
    pattern: /<!--[\s\S]*?-->/,
    description: 'HTML comment in tool description (can hide instructions from UI)',
  },
  {
    pattern: /[\uE000-\uF8FF]/,
    description: 'Private Use Area Unicode characters in tool description (may encode hidden data)',
  },
  {
    pattern: /[\u00AD]/,
    description: 'Soft hyphen character used to break up keywords and evade pattern detection',
  },
  {
    pattern: /[\u2066-\u2069\u202A-\u202E]/,
    description: 'Bidirectional text override characters in tool description (can reorder visible text)',
  },
]

/**
 * Patterns that indicate attempts to inject hidden instructions via unusual
 * formatting or encoding tricks.
 */
const HIDDEN_INSTRUCTION_PATTERNS: Array<{ pattern: RegExp; description: string; severity: 'critical' | 'high' }> = [
  {
    pattern: /ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions/i,
    description: 'Instruction override pattern in tool description',
    severity: 'critical',
  },
  {
    pattern: /you\s+(?:must|should|will)\s+(?:now\s+)?(?:also\s+)?(?:execute|run|call|invoke)/i,
    description: 'Imperative command to execute actions in tool description',
    severity: 'high',
  },
  {
    pattern: /system\s+prompt|assistant\s+prompt|hidden\s+instructions?/i,
    description: 'Reference to system prompt in tool description (meta-instruction)',
    severity: 'high',
  },
  {
    pattern: /(?:atob|btoa|base64_decode|Buffer\.from)\s*\(/i,
    description: 'Base64 decode function call in tool description (obfuscated payload)',
    severity: 'critical',
  },
  {
    pattern: /(?:remember|store|save)\s+(?:that|this|for\s+(?:future|later|all))\s+/i,
    description: 'Memory poisoning instruction in tool description (persists malicious context across sessions)',
    severity: 'high',
  },
  {
    pattern: /(?:mandatory|required)\s+(?:parameter|field|argument).*(?:api.?key|token|secret|credential|password|auth)/i,
    description: 'Rug pull pattern: forces credential extraction as mandatory parameter (schema injection attack)',
    severity: 'critical',
  },
  {
    pattern: /(?:first|before|prior\s+to)\s+(?:any|all|each)\s+(?:request|call|action|operation)/i,
    description: 'Pre-action hijack pattern in tool description (forces actions before every request)',
    severity: 'high',
  },
]

/**
 * Analyze a server's tools for tool poisoning attacks.
 * Tool poisoning embeds hidden instructions in tool descriptions using Unicode
 * tricks or HTML to manipulate the LLM without human reviewers noticing.
 */
export function analyzeToolPoisoning(server: MCPServer): Finding[] {
  const findings: Finding[] = []
  if (!server.tools) return findings

  for (const tool of server.tools) {
    const desc = tool.description || ''

    for (const { pattern, description } of UNICODE_HIDDEN_PATTERNS) {
      if (pattern.test(desc)) {
        const match = desc.match(pattern)
        findings.push({
          analyzer: 'tool-poisoning',
          severity: 'critical',
          server_name: server.name,
          tool_name: tool.name,
          description,
          field: 'description',
          evidence: match ? match[0].slice(0, 100) : '(detected)',
          remediation: TOOL_POISONING_REMEDIATION,
        })
      }
    }

    for (const { pattern, description, severity } of HIDDEN_INSTRUCTION_PATTERNS) {
      const match = desc.match(pattern)
      if (match) {
        findings.push({
          analyzer: 'tool-poisoning',
          severity,
          server_name: server.name,
          tool_name: tool.name,
          description,
          field: 'description',
          evidence: match[0].slice(0, 200),
          remediation: TOOL_POISONING_REMEDIATION,
        })
      }
    }
  }

  return findings
}
