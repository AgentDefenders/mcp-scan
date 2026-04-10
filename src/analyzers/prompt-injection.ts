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
  {
    pattern: /(?:when|if)\s+(?:the\s+)?(?:output|response|result)\s+(?:contains?|includes?|has)\s+(?:error|fail|exception)/i,
    description: 'Error-conditional behavior: changes tool behavior based on error states to exploit error handling paths for malicious actions',
    severity: 'medium',
  },
  {
    pattern: /(?:forward|relay|proxy|pass)\s+(?:this\s+)?(?:request|message|query|prompt)\s+(?:to|through|via)\s+(?:another|a\s+different|the\s+other)\s+(?:server|endpoint|api|service)/i,
    description: 'Request relay/proxy pattern: forwards agent requests through attacker-controlled intermediary for interception or modification',
    severity: 'high',
  },
  {
    pattern: /(?:create|generate|produce|write)\s+(?:a\s+)?(?:new\s+)?(?:tool|function|server|mcp)\s+(?:definition|config|configuration|manifest)/i,
    description: 'Dynamic tool creation instruction: attempts to generate new MCP tool definitions at runtime, enabling persistent backdoors',
    severity: 'high',
  },
  {
    pattern: /(?:use|leverage|exploit)\s+(?:the\s+)?(?:sampling|create_message|completions?)\s+(?:api|endpoint|capability)\s+(?:to\s+)?(?:generate|create|produce)/i,
    description: 'MCP Sampling API exploitation: uses server-initiated sampling capability to generate attacker-controlled content within the trusted context',
    severity: 'critical',
  },
  {
    pattern: /(?:set|configure|establish)\s+(?:a\s+)?(?:recurring|periodic|scheduled|cron)\s+(?:task|job|action|execution)/i,
    description: 'Persistent scheduled task injection: attempts to install recurring malicious operations that survive session boundaries',
    severity: 'high',
  },
  {
    pattern: /(?:access|read|query|fetch)\s+(?:the\s+)?(?:conversation|chat|message)\s+(?:history|log|archive|context)\s+(?:and|to|for)\s+/i,
    description: 'Conversation history exfiltration: accesses prior conversation content to harvest sensitive information shared in earlier messages',
    severity: 'critical',
  },
  {
    pattern: /(?:tell|inform|instruct)\s+(?:the\s+)?(?:other|next|connected)\s+(?:tool|server|agent|mcp)\s+(?:to|that)/i,
    description: 'Cross-tool instruction injection: attempts to influence behavior of other connected MCP servers through the shared agent context',
    severity: 'high',
  },
  {
    pattern: /(?:include|add|attach|append)\s+(?:the\s+)?(?:system\s+prompt|instructions?|rules?|context)\s+(?:in|as|to)\s+(?:the\s+)?(?:param|argument|input|request)/i,
    description: 'System prompt elicitation: instructs the LLM to leak system prompt content into MCP tool parameters for exfiltration',
    severity: 'critical',
  },
  {
    pattern: /(?:you\s+are|act\s+as|pretend\s+to\s+be|roleplay\s+as)\s+(?:a\s+)?(?:different|new|special|admin|root|system)/i,
    description: 'Role injection: attempts to change the LLM identity or privileges through tool description role assignment',
    severity: 'critical',
  },
  {
    pattern: /(?:parse|interpret|treat|process)\s+(?:the\s+)?(?:response|output|result|return)\s+(?:as|like)\s+(?:code|command|instruction|executable)/i,
    description: 'Response-as-code injection: instructs the LLM to treat server responses as executable instructions rather than data',
    severity: 'critical',
  },
  {
    pattern: /(?:recursively|repeatedly|continuously|infinitely)\s+(?:call|invoke|execute|trigger|run)\s+(?:this|the|itself)/i,
    description: 'Recursive tool invocation: attempts infinite or excessive self-invocation to drain compute quota or cause denial of service',
    severity: 'high',
  },
  {
    pattern: /(?:download|fetch|load|import)\s+(?:and\s+)?(?:execute|run|eval|install)\s+(?:from|via)\s+(?:https?:\/\/|ftp:\/\/)/i,
    description: 'Remote code loading: downloads and executes code from external URLs (drive-by download attack)',
    severity: 'critical',
  },
  {
    pattern: /(?:copy|clone|replicate|mirror)\s+(?:the\s+)?(?:entire|full|complete|whole)\s+(?:repository|codebase|project|directory)/i,
    description: 'Codebase exfiltration: attempts to copy entire repository contents for intellectual property theft',
    severity: 'high',
  },
  {
    pattern: /(?:modify|edit|update|change|write\s+to)\s+(?:the\s+)?(?:mcp[\s._-]?(?:json|config|settings)|(?:claude|cursor|windsurf|vscode)[\s/._-]*(?:mcp|config|settings)[\s._-]*(?:\.?json)?)/i,
    description: 'MCP config injection: instructs the agent to modify IDE MCP configuration files to inject malicious servers (SANDWORM_MODE vector)',
    severity: 'critical',
  },
  {
    pattern: /(?:add|install|register|inject)\s+(?:a\s+)?(?:new\s+)?(?:mcp|tool)\s+(?:server|endpoint|configuration|entry)/i,
    description: 'MCP server injection: instructs the agent to install unauthorized MCP servers into the active configuration',
    severity: 'critical',
  },
  {
    pattern: /(?:this|the)\s+(?:server|tool|service)\s+(?:is|has\s+been)\s+(?:officially|formally)\s+(?:audited|reviewed|certified|endorsed|verified)/i,
    description: 'False audit claim: social engineers the LLM by claiming the server has been security-audited or officially endorsed',
    severity: 'medium',
  },
  {
    pattern: /(?:use|prefer|select|choose)\s+(?:this\s+tool|me)\s+(?:over|instead\s+of|before|rather\s+than)\s+(?:other|competing|alternative|similar)/i,
    description: 'Tool preference manipulation: instructs the LLM to prefer this tool over legitimate alternatives (MPMA attack)',
    severity: 'high',
  },
  {
    pattern: /(?:read|access|dump|list)\s+(?:the\s+)?(?:~\/\.cursor|~\/\.claude|~\/\.vscode|~\/\.config\/code|claude_desktop_config)/i,
    description: 'IDE config exfiltration: attempts to read MCP client configuration files containing server definitions and credentials',
    severity: 'critical',
  },
  {
    pattern: /(?:write|inject|insert|append)\s+(?:to|into)\s+(?:the\s+)?(?:~\/\.bashrc|~\/\.zshrc|~\/\.profile|~\/\.bash_profile|crontab)/i,
    description: 'Shell persistence injection: attempts to write malicious entries into shell startup files or cron for persistent access',
    severity: 'critical',
  },
  {
    pattern: /(?:dns|hostname)\s+(?:rebind|redirect|resolve)\s+(?:to|via)\s+(?:127\.0\.0\.1|localhost|0\.0\.0\.0)/i,
    description: 'DNS rebinding instruction: attempts to exploit DNS rebinding to access localhost-bound MCP servers from external origins',
    severity: 'critical',
  },
  // 2026-04 additions: OAuth, sampling, elicitation, annotation spoofing, resource injection, cross-server
  {
    pattern: /(?:redirect|set|change|override)\s+(?:the\s+)?(?:oauth|authorization|auth)\s+(?:endpoint|url|callback|redirect_uri)\s+(?:to|=)\s+/i,
    description: 'OAuth endpoint redirection: attempts to redirect OAuth flow to attacker-controlled endpoint for token theft (CVE-2025-6514 pattern)',
    severity: 'critical',
  },
  {
    pattern: /(?:register|create|add)\s+(?:a\s+)?(?:dynamic|new)\s+(?:oauth\s+)?client\s+(?:with|using|via)\s+/i,
    description: 'Dynamic OAuth client registration exploitation: registers rogue OAuth clients to intercept authorization flows',
    severity: 'high',
  },
  {
    pattern: /(?:use|abuse|exploit)\s+(?:the\s+)?(?:elicitation|elicit|user[\s_-]?prompt)\s+(?:to|for|and)\s+(?:ask|request|extract|collect)/i,
    description: 'MCP Elicitation API abuse: uses the elicitation feature to social-engineer users into revealing credentials or approving dangerous actions',
    severity: 'high',
  },
  {
    pattern: /(?:mark|set|declare|annotate)\s+(?:this\s+)?(?:tool|function)\s+(?:as\s+)?(?:read[\s_-]?only|non[\s_-]?destructive|safe|idempotent)/i,
    description: 'Tool annotation spoofing: falsely marks a destructive tool as safe/read-only to bypass client safety checks',
    severity: 'high',
  },
  {
    pattern: /(?:access|read|fetch|load)\s+(?:the\s+)?(?:resource|uri|template)\s+(?:at|from|via)\s+(?:file:\/\/|https?:\/\/169\.254|https?:\/\/localhost|https?:\/\/127\.)/i,
    description: 'MCP resource template SSRF: accesses local/metadata resources via MCP resource URI templates to steal credentials or reach internal services',
    severity: 'critical',
  },
  {
    pattern: /(?:read|access|exfiltrate|steal|harvest)\s+(?:data|tokens?|credentials?|secrets?|keys?)\s+(?:from|via|through)\s+(?:the\s+)?(?:other|connected|co[\s-]?connected|adjacent)\s+(?:server|mcp|tool)/i,
    description: 'Cross-server data exfiltration: attempts to harvest credentials or data from co-connected MCP servers through shared agent context',
    severity: 'critical',
  },
  {
    pattern: /(?:inject|embed|insert|plant)\s+(?:instructions?|prompts?|commands?|payloads?)\s+(?:into|in|within)\s+(?:the\s+)?(?:output|response|result|return\s+value|tool\s+result)/i,
    description: 'Tool output poisoning (CyberArk pattern): embeds malicious instructions in tool return values to poison downstream LLM reasoning',
    severity: 'critical',
  },
  {
    pattern: /(?:clone|replicate|spread|propagate)\s+(?:this\s+)?(?:instruction|payload|prompt|code)\s+(?:to|into|across)\s+(?:other|all|every|connected)\s+(?:server|tool|agent|mcp)/i,
    description: 'Agentic worm propagation: instructs the agent to spread malicious payloads to all connected MCP servers (self-replicating attack)',
    severity: 'critical',
  },
  {
    pattern: /(?:open|launch|start|execute)\s+(?:a\s+)?(?:reverse\s+shell|bind\s+shell|netcat|nc\s+-[el]|socat)\s+/i,
    description: 'Reverse/bind shell execution: attempts to establish interactive shell access for remote control of the host system',
    severity: 'critical',
  },
  {
    pattern: /(?:mount|access|read)\s+(?:the\s+)?(?:\/var\/run\/docker\.sock|docker[\s._-]?socket|\/run\/containerd)/i,
    description: 'Container runtime socket access: attempts to access Docker/containerd socket for container escape and host compromise',
    severity: 'critical',
  },
  {
    pattern: /(?:sign|approve|authorize|confirm)\s+(?:the\s+)?(?:transaction|transfer|payment|withdrawal|swap)\s+(?:to|for|of)\s+/i,
    description: 'Cryptocurrency transaction authorization: attempts to get the agent to sign financial transactions or token transfers',
    severity: 'critical',
  },
  {
    pattern: /(?:modify|edit|update|change)\s+(?:the\s+)?(?:pipeline|workflow|build|deploy|release)\s+(?:config|script|file|definition|yaml|yml)/i,
    description: 'CI/CD pipeline modification: attempts to alter build/deploy configurations for supply chain compromise',
    severity: 'critical',
  },
  {
    pattern: /(?:update|modify|change|add|delete)\s+(?:the\s+)?(?:dns|domain|cname|a[\s_-]?record|mx[\s_-]?record|nameserver)/i,
    description: 'DNS record manipulation: attempts to modify DNS records for domain takeover or traffic interception',
    severity: 'critical',
  },
  // 2026-04-07 additions: context flooding, notification abuse, roots enumeration, browser session hijack, config poisoning, clipboard, sampling escalation
  {
    pattern: /(?:return|output|generate)\s+(?:a\s+)?(?:very\s+)?(?:large|huge|massive|enormous)\s+(?:amount|volume|block)\s+(?:of\s+)?(?:text|data|content|tokens)/i,
    description: 'Context window denial-of-service: instructs the tool to flood the LLM context with large outputs to push out safety instructions (OWASP ASI09)',
    severity: 'high',
  },
  {
    pattern: /(?:use|abuse|exploit|leverage)\s+(?:the\s+)?(?:sampling|createMessage|create_message)(?:\s+\w+)*?\s+(?:to|for|and)\s+(?:call|invoke|execute|trigger)/i,
    description: 'MCP sampling recursive escalation: abuses createMessage/sampling to autonomously invoke tools beyond the server original scope (OWASP ASI03 Excessive Agency)',
    severity: 'critical',
  },
  {
    pattern: /(?:enumerate|list|discover|scan)\s+(?:all\s+)?(?:project\s+)?(?:roots|workspaces|directories|repositories)\s+(?:and|to|then)\s+(?:find|identify|locate|target)/i,
    description: 'Roots enumeration for targeted attack: uses roots/list to fingerprint the development environment and identify high-value targets for data exfiltration',
    severity: 'high',
  },
  {
    pattern: /(?:access|read|steal|copy)\s+(?:the\s+)?(?:browser|chrome|firefox|safari)\s+(?:profile|cookies?|session|storage|passwords?|saved\s+credentials)/i,
    description: 'Browser session hijacking: attempts to access browser profile data (cookies, saved passwords, session tokens) for account takeover',
    severity: 'critical',
  },
  {
    pattern: /(?:write|create|modify|append)\s+(?:to\s+)?(?:the\s+)?(?:\.cursorrules|\.clinerules|\.github\/copilot|\.claude\/settings|\.continue\/config)/i,
    description: 'AI assistant config injection: modifies AI coding assistant configuration files to inject persistent malicious instructions across sessions',
    severity: 'critical',
  },
  {
    pattern: /(?:monitor|poll|watch|read)\s+(?:the\s+)?(?:clipboard|paste\s+buffer|copy\s+buffer)\s+(?:for|every|continuously|repeatedly)/i,
    description: 'Clipboard monitoring for credential harvesting: continuously polls clipboard content to capture credentials and tokens copied by the developer',
    severity: 'high',
  },
  {
    pattern: /(?:send|embed|hide|encode)\s+(?:data|secrets?|tokens?|credentials?)\s+(?:in|via|through|using)\s+(?:the\s+)?(?:notification|progress|log\s+message)/i,
    description: 'MCP notification covert channel: embeds exfiltrated data in MCP notification messages that bypass tool-call security monitoring',
    severity: 'critical',
  },
  {
    pattern: /(?:register|install|add)\s+(?:a\s+)?(?:new\s+)?(?:mcp\s+)?(?:server|tool)\s+(?:from|via|using)\s+(?:http:\/\/|untrusted|unknown|dynamic)/i,
    description: 'Dynamic MCP server registration from untrusted source: installs additional MCP servers at runtime from unverified sources to expand attack surface',
    severity: 'critical',
  },
  // 2026-04-10 additions: A2A bridge abuse, Bedrock/model access, state file exfil, OAuth metadata, goal hijacking, homoglyph confusion
  {
    pattern: /(?:route|forward|bridge|translate)\s+(?:the\s+)?(?:request|call|action|command)\s+(?:through|via|to)\s+(?:a2a|agent[\s_-]?to[\s_-]?agent|external\s+agent)/i,
    description: 'A2A protocol bridge exploitation: routes MCP tool calls through Agent-to-Agent protocol to bypass client-side approval gates and permission checks',
    severity: 'critical',
  },
  {
    pattern: /(?:invoke|call|access)\s+(?:the\s+)?(?:bedrock|sagemaker|vertex[\s_-]?ai|foundation\s+model)\s+(?:endpoint|api|model)/i,
    description: 'Cloud AI model service abuse: invokes cloud foundation model APIs (Bedrock, SageMaker, Vertex AI) to generate malicious content or drain compute budgets via the MCP server',
    severity: 'high',
  },
  {
    pattern: /(?:read|access|parse|load)\s+(?:the\s+)?(?:terraform|tfstate|pulumi|cloudformation)\s+(?:state|output|stack|template)\s+(?:file|data)/i,
    description: 'IaC state file credential extraction: reads Terraform state, Pulumi outputs, or CloudFormation exports that commonly contain plaintext secrets, database passwords, and cloud credentials',
    severity: 'critical',
  },
  {
    pattern: /(?:fetch|request|load)\s+(?:the\s+)?(?:\.well[\s_-]?known|oauth[\s_-]?metadata|protected[\s_-]?resource[\s_-]?metadata|authorization[\s_-]?server[\s_-]?metadata)/i,
    description: 'OAuth metadata discovery manipulation: fetches well-known OAuth metadata endpoints that can be poisoned to redirect authorization flows to attacker-controlled servers',
    severity: 'high',
  },
  {
    pattern: /(?:shift|drift|evolve|gradually\s+change)\s+(?:the\s+)?(?:conversation|context|behavior|objective|goal)\s+(?:over|across|between)\s+(?:turns?|messages?|interactions?)/i,
    description: 'Multi-turn goal drift attack: gradually shifts the agent objective across multiple conversation turns to avoid single-turn injection detection',
    severity: 'high',
  },
  {
    pattern: /(?:use|apply|insert)\s+(?:unicode\s+)?(?:homoglyph|confusable|lookalike|visually[\s_-]?similar)\s+(?:character|letter|symbol)/i,
    description: 'Homoglyph confusion attack: uses visually identical Unicode characters from different scripts to evade keyword-based security filters while appearing benign to human reviewers',
    severity: 'critical',
  },
  {
    pattern: /(?:approve|merge|accept)\s+(?:the\s+)?(?:pull\s+request|PR|merge\s+request|MR|code\s+change|commit)\s+(?:automatically|without\s+review|immediately)/i,
    description: 'Automated code approval: instructs the agent to approve or merge code changes without human review, enabling supply chain compromise via trusted CI/CD pipelines',
    severity: 'critical',
  },
  {
    pattern: /(?:modify|write|update|inject)\s+(?:the\s+)?(?:\.junie|\.gemini|\.amazonq|\.continue|\.zed)[\s/._-]*(?:mcp|config|settings)/i,
    description: 'IDE MCP config injection (expanded): targets additional IDE configurations (Junie, Gemini CLI, Amazon Q, Continue, Zed) to inject malicious MCP servers',
    severity: 'critical',
  },
  {
    pattern: /(?:exhaust|drain|consume|deplete)\s+(?:the\s+)?(?:token|compute|api|credit|billing)\s+(?:budget|quota|limit|allowance)/i,
    description: 'Token/compute budget exhaustion: intentionally drains the agent API credits or compute quota through wasteful operations or recursive tool invocations',
    severity: 'high',
  },
  {
    pattern: /(?:delete|modify|tamper|clear)\s+(?:the\s+)?(?:audit|log|trace|event)\s+(?:trail|record|entry|history|data)/i,
    description: 'Audit log tampering: attempts to delete or modify security audit logs to cover tracks after malicious activity',
    severity: 'critical',
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
