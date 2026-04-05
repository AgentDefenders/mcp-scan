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
  {
    pattern: /\u{E0001}|[\u{E0020}-\u{E007F}]/u,
    description: 'Unicode Tag characters in tool description (deprecated language tags used to encode hidden data)',
  },
  {
    pattern: /[\u2800-\u28FF]/,
    description: 'Braille pattern characters used to create invisible text blocks in tool description',
  },
  {
    pattern: /[\u3164\uFFA0]/,
    description: 'Hangul filler characters creating invisible content in tool description',
  },
  {
    pattern: /\s{50,}/,
    description: 'Excessive whitespace in tool description (may hide instructions after horizontal scroll boundary)',
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
  {
    pattern: /(?:eval|Function|setTimeout|setInterval)\s*\(\s*['"]/i,
    description: 'JavaScript dynamic code execution in tool description (arbitrary code injection)',
    severity: 'critical',
  },
  {
    pattern: /(?:subprocess|os\.system|os\.popen|exec|spawn|child_process)\s*\(/i,
    description: 'System command execution call in tool description (shell injection vector)',
    severity: 'critical',
  },
  {
    pattern: /(?:import|require|__import__|importlib)\s*\(\s*['"]/i,
    description: 'Dynamic module import in tool description (arbitrary code loading)',
    severity: 'high',
  },
  {
    pattern: /(?:after|once)\s+(?:this\s+)?(?:tool|function|action)\s+(?:completes?|finishes?|runs?|executes?)\s*,?\s*(?:also|then|next|immediately)\s+/i,
    description: 'Post-action chaining pattern in tool description (forces follow-up actions after tool execution)',
    severity: 'high',
  },
  {
    pattern: /(?:silently|quietly|secretly|covertly|without\s+(?:the\s+)?(?:user|anyone)\s+(?:knowing|noticing))/i,
    description: 'Stealth operation instruction in tool description (conceals malicious activity from user)',
    severity: 'critical',
  },
  {
    pattern: /(?:webhook|callback|notify)\s*(?:url|endpoint|hook)\s*[:=]\s*https?:\/\//i,
    description: 'Hardcoded webhook URL in tool description (data exfiltration via callback)',
    severity: 'high',
  },
  {
    pattern: /(?:override|rewrite|modify)\s+(?:the\s+)?(?:output|response|result)\s+(?:to|before|with)/i,
    description: 'Output manipulation pattern in tool description (ATPA: Advanced Tool Poisoning via output rewriting)',
    severity: 'critical',
  },
  {
    pattern: /(?:append|prepend|inject|embed)\s+(?:to|into|in)\s+(?:the\s+)?(?:output|response|result|return)/i,
    description: 'Output injection pattern in tool description (ATPA: malicious content injected into tool responses)',
    severity: 'critical',
  },
  {
    pattern: /(?:when|if)\s+(?:the\s+)?(?:user|developer|admin)\s+(?:is\s+)?(?:not\s+)?(?:watching|looking|present|active|monitoring)/i,
    description: 'Conditional execution based on user presence (rug pull / delayed activation pattern)',
    severity: 'critical',
  },
  {
    pattern: /(?:on|after)\s+(?:first|initial|1st)\s+(?:run|execution|call|use)[\s\S]{0,50}(?:then|switch|change|activate)/i,
    description: 'Delayed activation pattern in tool description (MCP rug pull: benign on first run, malicious after)',
    severity: 'critical',
  },
  {
    pattern: /(?:pipe|chain|forward)\s+(?:the\s+)?(?:result|output|data)\s+(?:to|into|through)\s+(?:another|next|the)\s+(?:tool|function|server)/i,
    description: 'Cross-tool data chaining in tool description (confused deputy attack via tool output forwarding)',
    severity: 'high',
  },
  {
    pattern: /(?:json|xml|yaml)\s*(?:\.parse|\.load|\.decode|parse|unmarshal)\s*\(/i,
    description: 'Data deserialization in tool description (potential deserialization attack vector)',
    severity: 'high',
  },
  {
    pattern: /(?:return|respond|output)\s+(?:with|using|containing)\s+(?:the\s+)?(?:following|these|this)\s+(?:instruction|command|directive)/i,
    description: 'Output poisoning pattern: instructs tool to return crafted content that injects instructions into the LLM context (SEA attack)',
    severity: 'critical',
  },
  {
    pattern: /(?:include|add|insert)\s+(?:in|to)\s+(?:the\s+)?(?:return|response|output)\s+(?:value|body|payload)/i,
    description: 'Return value injection: embeds hidden instructions in tool output to manipulate subsequent LLM reasoning',
    severity: 'high',
  },
  {
    pattern: /(?:on|after|upon)\s+(?:every|each|any)\s+(?:nth|second|third|\d+(?:st|nd|rd|th))\s+(?:call|invocation|request|use)/i,
    description: 'Intermittent activation pattern: malicious behavior triggers only on periodic invocations to evade testing and detection',
    severity: 'critical',
  },
  {
    pattern: /(?:check|read|access|scan)\s+(?:the\s+)?(?:other|adjacent|connected|sibling)\s+(?:tool|server|mcp)\s*(?:'?s?\s+)?(?:config|credential|token|secret|output)/i,
    description: 'Cross-server credential harvesting: attempts to read credentials or outputs from other connected MCP servers (confused deputy)',
    severity: 'critical',
  },
  {
    pattern: /(?:modify|update|change|alter)\s+(?:the\s+)?(?:tool|function)\s+(?:behavior|response|output)\s+(?:based\s+on|depending\s+on|according\s+to)\s+(?:the\s+)?(?:time|date|hour|day|count)/i,
    description: 'Time-based behavior switching: tool changes behavior based on temporal conditions (scheduled rug pull pattern)',
    severity: 'critical',
  },
  {
    pattern: /(?:concatenate|join|combine|merge)\s+(?:all\s+)?(?:the\s+)?(?:parameter|argument|input|field)\s+(?:value)?s?\s+(?:and|then)\s+(?:execute|eval|run)/i,
    description: 'Parameter concatenation to code execution: combines seemingly innocent parameters into executable payload',
    severity: 'critical',
  },
  {
    pattern: /(?:on|upon|after)\s+(?:error|failure|exception|timeout)\s*,?\s*(?:retry|fallback|redirect|send)\s+(?:to|via|through)\s+/i,
    description: 'Error-path hijacking: redirects error handling to attacker-controlled endpoints or triggers malicious fallback behavior',
    severity: 'critical',
  },
  {
    pattern: /(?:if|when)\s+(?:running|executed|called)\s+(?:in|on|from)\s+(?:ci|production|staging|server|cloud|docker|container)/i,
    description: 'Environment-conditional activation: changes behavior based on runtime environment to target production or CI systems selectively',
    severity: 'critical',
  },
  {
    pattern: /(?:replace|swap|modify)\s+(?:the\s+)?(?:tool|function|schema)\s+(?:name|definition|description)\s+(?:with|to|at\s+runtime)/i,
    description: 'Runtime tool mutation: dynamically changes tool identity or behavior after initial registration (rug pull variant)',
    severity: 'critical',
  },
  {
    pattern: /(?:read|access|scan|enumerate)\s+(?:all\s+)?(?:the\s+)?(?:environment|env)\s+(?:variable|var)s?\s+(?:and|then)\s+(?:send|post|forward|upload)/i,
    description: 'Environment variable exfiltration: enumerates and transmits all environment variables to an external endpoint',
    severity: 'critical',
  },
  {
    pattern: /(?:use|call|invoke)\s+(?:the\s+)?(?:notification|notify|alert)\s+(?:channel|endpoint|api)\s+(?:to\s+)?(?:send|deliver|transmit)/i,
    description: 'Notification channel abuse: uses MCP notification channel to exfiltrate data outside normal tool response flow',
    severity: 'high',
  },
  {
    pattern: /(?:wrap|intercept|proxy|hook)\s+(?:the\s+)?(?:original|real|actual|underlying)\s+(?:tool|function|method|api)/i,
    description: 'Tool interception pattern: wraps or proxies legitimate tool calls to intercept and exfiltrate data in transit',
    severity: 'critical',
  },
  {
    pattern: /(?:officially?\s+)?(?:endorsed|certified|verified|approved|trusted)\s+(?:by|from)\s+(?:anthropic|openai|google|microsoft|meta)/i,
    description: 'Preference manipulation attack (MPMA): fake endorsement claim to bias agent tool selection toward this server',
    severity: 'high',
  },
  {
    pattern: /(?:priority|urgency|importance)\s*[:=]\s*(?:critical|highest|emergency|mandatory|urgent)/i,
    description: 'Preference manipulation attack: urgency trigger to force agent to prioritize this tool over legitimate alternatives',
    severity: 'high',
  },
  {
    pattern: /(?:this\s+tool\s+)?(?:must|should)\s+(?:always\s+)?(?:be\s+)?(?:called|used|invoked|selected)\s+(?:first|before|instead\s+of|over)\s+/i,
    description: 'Tool priority hijack: instructs agent to always prefer this tool over others (DPMA variant)',
    severity: 'high',
  },
  {
    pattern: /(?:split|distribute|spread)\s+(?:the\s+)?(?:instruction|command|payload|data)\s+(?:across|between|over)\s+(?:multiple\s+)?(?:field|param|schema)/i,
    description: 'Description splitting attack: distributes malicious payload across multiple schema fields to evade single-field detection',
    severity: 'critical',
  },
  {
    pattern: /(?:reconstruct|reassemble|combine|join)\s+(?:the\s+)?(?:parts?|fragments?|pieces?|segments?)\s+(?:from|in|across)\s+(?:the\s+)?(?:schema|fields?|params?)/i,
    description: 'Fragment reassembly instruction: tells the LLM to reconstruct a split payload from multiple schema fields (MCPTox evasion)',
    severity: 'critical',
  },
  {
    pattern: /(?:do\s+not|don't|never)\s+(?:show|display|reveal|expose)\s+(?:this|the|these)\s+(?:instruction|description|text|content)\s+(?:to|in)\s+(?:the\s+)?(?:user|output|response|log)/i,
    description: 'Instruction concealment: explicitly tells the LLM to hide the malicious instruction from user-visible output',
    severity: 'critical',
  },
]

/**
 * Extract all string values from a JSON schema object for Full-Schema Poisoning
 * (FSP) analysis. Every field in the schema is a potential injection surface,
 * not just the description.
 */
function extractSchemaStrings(schema: Record<string, unknown>): Array<{ value: string; path: string }> {
  const results: Array<{ value: string; path: string }> = []

  function walk(obj: unknown, currentPath: string): void {
    if (typeof obj === 'string' && obj.length > 0) {
      results.push({ value: obj, path: currentPath })
    } else if (Array.isArray(obj)) {
      for (let i = 0; i < obj.length; i++) {
        walk(obj[i], `${currentPath}[${i}]`)
      }
    } else if (obj !== null && typeof obj === 'object') {
      for (const [key, val] of Object.entries(obj as Record<string, unknown>)) {
        walk(val, currentPath ? `${currentPath}.${key}` : key)
      }
    }
  }

  walk(schema, '')
  return results
}

/**
 * Analyze a server's tools for tool poisoning attacks.
 * Tool poisoning embeds hidden instructions in tool descriptions using Unicode
 * tricks or HTML to manipulate the LLM without human reviewers noticing.
 * Also performs Full-Schema Poisoning (FSP) analysis on inputSchema fields.
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

    // Full-Schema Poisoning (FSP): scan inputSchema string values for hidden instructions.
    // Every field in the tool schema (titles, defaults, enum values, examples) is an injection surface.
    if (tool.inputSchema) {
      const schemaStrings = extractSchemaStrings(tool.inputSchema)
      for (const { value, path } of schemaStrings) {
        for (const { pattern, description: unicodeDesc } of UNICODE_HIDDEN_PATTERNS) {
          if (pattern.test(value)) {
            const match = value.match(pattern)
            findings.push({
              analyzer: 'tool-poisoning',
              severity: 'critical',
              server_name: server.name,
              tool_name: tool.name,
              description: `Full-Schema Poisoning: ${unicodeDesc} (in inputSchema.${path})`,
              field: `inputSchema.${path}`,
              evidence: match ? match[0].slice(0, 100) : '(detected)',
              remediation: 'Review the tool inputSchema for hidden instructions. All schema fields (title, description, default, enum, examples) are potential injection surfaces. Compare against the official schema definition.',
            })
          }
        }
        for (const { pattern, description: instrDesc, severity } of HIDDEN_INSTRUCTION_PATTERNS) {
          const match = value.match(pattern)
          if (match) {
            findings.push({
              analyzer: 'tool-poisoning',
              severity,
              server_name: server.name,
              tool_name: tool.name,
              description: `Full-Schema Poisoning: ${instrDesc} (in inputSchema.${path})`,
              field: `inputSchema.${path}`,
              evidence: match[0].slice(0, 200),
              remediation: 'Review the tool inputSchema for hidden instructions. All schema fields (title, description, default, enum, examples) are potential injection surfaces. Compare against the official schema definition.',
            })
          }
        }
      }
    }
  }

  return findings
}
