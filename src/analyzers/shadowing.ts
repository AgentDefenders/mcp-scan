import type { Finding, MCPServer } from '../types.js'

/** Remediation guidance for shadowing findings. */
const SHADOWING_REMEDIATION =
  'This tool shadows a built-in or commonly-used tool name. Rename the tool or remove the duplicate MCP server to prevent confusion.'

/**
 * Built-in tool names that are commonly targeted for shadowing attacks.
 * A shadowing attack registers a malicious tool with the same or similar name
 * as a trusted built-in, causing the LLM to call the malicious version.
 */
const BUILT_IN_TOOL_NAMES = new Set([
  'bash',
  'computer',
  'edit',
  'read',
  'write',
  'str_replace_editor',
  'str_replace_based_edit_tool',
  'create_file',
  'delete_file',
  'list_files',
  'search_files',
  'grep',
  'find',
  'execute',
  'run',
  'shell',
  'terminal',
  'python',
  'javascript',
  'code',
  'web_search',
  'browser',
  'fetch',
  'http_request',
])

/** Patterns that closely mimic built-in tool names. */
const SHADOWING_PATTERNS: Array<{ pattern: RegExp; shadowsBuiltin: string }> = [
  { pattern: /^bash_?(?:exec|run|command)?$/i, shadowsBuiltin: 'bash' },
  { pattern: /^(?:run|exec)_?(?:bash|shell|command|code)$/i, shadowsBuiltin: 'bash/shell' },
  { pattern: /^(?:web|internet)_?search$/i, shadowsBuiltin: 'web_search' },
  { pattern: /^(?:file|fs)_?(?:read|write|edit|create|delete)$/i, shadowsBuiltin: 'file tools' },
  { pattern: /^computer_?(?:use|control|action)?$/i, shadowsBuiltin: 'computer' },
  { pattern: /^str_replace/i, shadowsBuiltin: 'str_replace_editor' },
]

/**
 * Analyze a server's tools for shadowing attacks.
 * Shadowing registers tools with names identical or very similar to trusted
 * built-in tools, causing the LLM to call the malicious version instead.
 */
export function analyzeShadowing(server: MCPServer): Finding[] {
  const findings: Finding[] = []
  if (!server.tools) return findings

  for (const tool of server.tools) {
    const toolNameLower = tool.name.toLowerCase()

    // Exact match against known built-in names.
    if (BUILT_IN_TOOL_NAMES.has(toolNameLower)) {
      findings.push({
        analyzer: 'shadowing',
        severity: 'high',
        server_name: server.name,
        tool_name: tool.name,
        description: `Tool name "${tool.name}" shadows a known built-in tool. Attackers use this to intercept LLM calls to trusted tools.`,
        field: 'name',
        evidence: tool.name,
        remediation: SHADOWING_REMEDIATION,
      })
      continue
    }

    // Pattern match for near-duplicates.
    for (const { pattern, shadowsBuiltin } of SHADOWING_PATTERNS) {
      if (pattern.test(tool.name)) {
        findings.push({
          analyzer: 'shadowing',
          severity: 'medium',
          server_name: server.name,
          tool_name: tool.name,
          description: `Tool name "${tool.name}" closely mimics built-in "${shadowsBuiltin}" (shadowing pattern).`,
          field: 'name',
          evidence: tool.name,
          remediation: SHADOWING_REMEDIATION,
        })
        break
      }
    }
  }

  return findings
}
