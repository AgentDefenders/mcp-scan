import type { Finding, MCPServer } from '../types.js'

/**
 * Prompt injection patterns: strings that attempt to override the LLM's
 * instructions or manipulate its behavior through the tool description.
 */
const PROMPT_INJECTION_PATTERNS: Array<{ pattern: RegExp; description: string; severity: 'critical' | 'high' | 'medium' }> = [
  {
    pattern: /\[SYSTEM\]|\[INST\]|<\|im_start\|>|<\|system\|>/i,
    description: 'LLM special token in tool description (attempts to inject system context)',
    severity: 'critical',
  },
  {
    pattern: /###\s*(?:system|user|assistant|instruction)/i,
    description: 'Chat format role header in tool description (prompt injection pattern)',
    severity: 'critical',
  },
  {
    pattern: /disregard\s+(?:the\s+)?(?:above|previous|prior|all)\s+(?:instructions?|context|rules?)/i,
    description: 'Instruction disregard pattern in tool description',
    severity: 'critical',
  },
  {
    pattern: /(?:do\s+not|don't|never)\s+(?:tell|inform|mention|reveal|disclose)\s+(?:the\s+)?user/i,
    description: 'Instruction to conceal actions from user in tool description',
    severity: 'high',
  },
  {
    pattern: /send\s+(?:all\s+)?(?:the\s+)?(?:conversation|messages?|context|data)\s+to/i,
    description: 'Data exfiltration instruction in tool description',
    severity: 'critical',
  },
  {
    pattern: /(?:always|must|should)\s+(?:first|also|additionally)\s+(?:call|invoke|execute|run)\s+(?:this|the|another)\s+tool/i,
    description: 'Forced tool chaining instruction in tool description',
    severity: 'high',
  },
  {
    pattern: /when\s+(?:asked|prompted|requested)\s+(?:to\s+)?(?:do|perform|execute)/i,
    description: 'Conditional instruction override pattern in tool description',
    severity: 'medium',
  },
]

/**
 * Analyze a server's tools for prompt injection attacks in descriptions.
 * Prompt injection uses tool descriptions to override LLM instructions.
 */
export function analyzePromptInjection(server: MCPServer): Finding[] {
  const findings: Finding[] = []
  if (!server.tools) return findings

  for (const tool of server.tools) {
    const desc = tool.description || ''

    for (const { pattern, description, severity } of PROMPT_INJECTION_PATTERNS) {
      const match = desc.match(pattern)
      if (match) {
        findings.push({
          analyzer: 'prompt-injection',
          severity,
          server_name: server.name,
          tool_name: tool.name,
          description,
          field: 'description',
          evidence: match[0].slice(0, 200),
        })
      }
    }
  }

  return findings
}
