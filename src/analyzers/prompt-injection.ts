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
  {
    pattern: /(?:read|access|dump|list|scan|search)\s+(?:all\s+)?(?:files?\s+in\s+)?(?:\/etc\/|\/root\/|~\/\.ssh|~\/\.aws|~\/\.config|~\/\.gnupg)/i,
    description: 'Sensitive filesystem path access pattern (credential harvesting from known secret locations)',
    severity: 'critical',
  },
  {
    pattern: /(?:curl|wget|fetch|post|send)\s+(?:.*\s+)?(?:to\s+)?https?:\/\//i,
    description: 'Outbound HTTP request instruction in tool description (data exfiltration channel)',
    severity: 'high',
  },
  {
    pattern: /(?:do\s+not|don't|never)\s+(?:log|record|audit|trace|report)/i,
    description: 'Audit evasion instruction in tool description (attempts to suppress logging)',
    severity: 'high',
  },
  {
    pattern: /(?:before|after)\s+(?:responding|answering|replying)\s+(?:to\s+)?(?:the\s+)?user/i,
    description: 'Response interception pattern (injects actions before/after user interactions)',
    severity: 'medium',
  },
  {
    pattern: /(?:execute|run|eval|exec)\s*\(\s*(?:input|param|arg|data|request|query)/i,
    description: 'Dynamic code execution pattern in tool description (arbitrary code execution risk)',
    severity: 'critical',
  },
  {
    pattern: /(?:replace|swap|substitute)\s+(?:the\s+)?(?:response|output|result|answer)\s+(?:with|to|for)/i,
    description: 'Response substitution pattern in tool description (output manipulation attack)',
    severity: 'high',
  },
  {
    pattern: /(?:ignore|bypass|skip|disable)\s+(?:all\s+)?(?:security|auth|permission|access\s+control|validation|verification)/i,
    description: 'Security bypass instruction in tool description (attempts to disable security controls)',
    severity: 'critical',
  },
  {
    pattern: /(?:grant|give|provide|enable)\s+(?:full|admin|root|superuser|elevated)\s+(?:\w+\s+)?(?:access|permission|privilege)/i,
    description: 'Privilege escalation instruction in tool description (requests unauthorized elevated access)',
    severity: 'critical',
  },
  {
    pattern: /(?:sample|sampling|create_message|createMessage)\s*\(.*(?:inject|override|ignore|system)/i,
    description: 'MCP Sampling abuse pattern: uses sampling/create_message to inject prompts into the LLM context',
    severity: 'critical',
  },
  {
    pattern: /(?:use|call|invoke)\s+(?:the\s+)?(?:sampling|create_message)\s+(?:to|and|for)\s+/i,
    description: 'MCP Sampling-based injection: instructs the agent to use sampling capabilities for unauthorized actions',
    severity: 'high',
  },
  {
    pattern: /(?:store|persist|write|save)\s+(?:this|the|these)\s+(?:instruction|rule|directive|command)s?\s+(?:to|in|into)\s+(?:memory|context|rag|knowledge|vector)/i,
    description: 'RAG/memory poisoning: attempts to persist malicious instructions in vector stores or knowledge bases',
    severity: 'critical',
  },
  {
    pattern: /(?:whenever|every\s+time|each\s+time|always)\s+(?:a\s+)?(?:user|developer|anyone)\s+(?:asks?|requests?|queries?|mentions?)/i,
    description: 'Persistent behavioral override: installs a standing instruction that triggers on future user interactions',
    severity: 'high',
  },
  {
    pattern: /(?:this\s+tool|I)\s+(?:am|is)\s+(?:a\s+)?(?:trusted|safe|verified|official|authorized)\s+/i,
    description: 'Trust escalation claim in tool description (social engineering the LLM into trusting the tool)',
    severity: 'medium',
  },
  {
    pattern: /(?:do\s+not|don't|never)\s+(?:ask|prompt|require|request)\s+(?:for\s+)?(?:confirmation|approval|permission|consent)/i,
    description: 'Approval bypass instruction: attempts to skip human-in-the-loop confirmation for sensitive actions',
    severity: 'critical',
  },
  {
    pattern: /(?:encode|convert|transform)\s+(?:the\s+)?(?:output|response|data|result)\s+(?:to|as|in|into)\s+(?:base64|hex|url.?encod|rot13)/i,
    description: 'Output encoding instruction: attempts to obfuscate exfiltrated data via encoding to evade content filters',
    severity: 'high',
  },
  {
    pattern: /(?:embed|hide|conceal|include)\s+(?:the\s+)?(?:data|output|result|secret|credential)\s+(?:in|inside|within)\s+(?:the\s+)?(?:image|url|link|markdown|html)/i,
    description: 'Steganographic exfiltration: attempts to hide stolen data in images, URLs, or markup',
    severity: 'critical',
  },
  {
    pattern: /(?:render|display|show|output)\s+(?:an?\s+)?(?:image|img|markdown\s+image)\s+(?:from|with|using)\s+(?:https?:\/\/|data:)/i,
    description: 'Image-based exfiltration via markdown rendering: encodes stolen data in image URL parameters',
    severity: 'high',
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
