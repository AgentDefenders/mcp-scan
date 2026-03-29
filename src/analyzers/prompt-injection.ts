import type { Finding, MCPServer } from '../types.js'

/** Remediation guidance for prompt-injection findings. */
const PROMPT_INJECTION_REMEDIATION =
  'The tool description contains instructions that could manipulate the AI model. Remove or sanitize the injected content. Pin the MCP server version to prevent future modifications.'

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
  {
    pattern: /(?:extract|include|pass|send|forward)\s+(?:the\s+)?(?:api.?key|token|secret|credential|password|auth\w*|bearer)\s+/i,
    description: 'Credential extraction instruction in tool description (rug pull attack vector)',
    severity: 'critical',
  },
  {
    pattern: /(?:fetch|request|access|connect\s+to)\s+(?:https?:\/\/)?169\.254\.169\.254/i,
    description: 'Cloud metadata service access pattern (SSRF for AWS/GCP credential theft)',
    severity: 'critical',
  },
  {
    pattern: /(?:security|safety)\s+(?:is|should\s+be)\s+(?:less\s+important|secondary|optional|disabled)/i,
    description: 'Memory poisoning: attempts to downgrade security posture in agent memory',
    severity: 'critical',
  },
  {
    pattern: /(?:pipe|redirect|forward|copy|mirror|replicate)\s+(?:all\s+)?(?:output|results?|responses?|data|content)\s+(?:to|through|via)\s+/i,
    description: 'Data mirroring instruction in tool description (exfiltration via output redirection)',
    severity: 'high',
  },
  {
    pattern: /(?:add|insert|include|inject)\s+(?:a\s+)?(?:bcc|cc|copy|header)\s+/i,
    description: 'Email/request header injection pattern (BCC exfiltration attack)',
    severity: 'high',
  },
  {
    pattern: /(?:override|replace|modify|change|update)\s+(?:the\s+)?(?:tool|function|schema|definition|parameter)/i,
    description: 'Dynamic tool redefinition instruction (rug pull / schema modification attack)',
    severity: 'high',
  },
  {
    pattern: /(?:use|prefer|switch\s+to|connect\s+via)\s+(?:this|my|the\s+following)\s+(?:endpoint|server|url|api|proxy)/i,
    description: 'Endpoint redirection pattern in tool description (man-in-the-middle attack)',
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
          remediation: PROMPT_INJECTION_REMEDIATION,
        })
      }
    }
  }

  return findings
}
