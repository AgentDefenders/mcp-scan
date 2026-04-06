import type { Finding, MCPServer, Severity } from '../types.js'

/** Remediation guidance for suspicious-env findings. */
const SUSPICIOUS_ENV_REMEDIATION =
  'This MCP server accesses sensitive environment variables at runtime. Review whether the server legitimately needs these variables. Consider using a sandboxed environment or restricting env var access.'

interface EnvRule {
  pattern: RegExp
  severity: Severity
  description: string
}

/**
 * Dangerous environment variable patterns.
 * Order matters: more severe checks first (critical > high > medium).
 */
const ENV_RULES: EnvRule[] = [
  // Critical: arbitrary native code injection
  {
    pattern: /^LD_PRELOAD$/,
    severity: 'critical',
    description: 'LD_PRELOAD allows injecting arbitrary shared libraries into every process started by this server',
  },
  {
    pattern: /^DYLD_INSERT_LIBRARIES$/,
    severity: 'critical',
    description: 'DYLD_INSERT_LIBRARIES is the macOS equivalent of LD_PRELOAD -- injects arbitrary dylibs',
  },
  // High: binary / library hijacking
  {
    pattern: /^LD_LIBRARY_PATH$/,
    severity: 'high',
    description: 'LD_LIBRARY_PATH can redirect shared library loading to attacker-controlled paths',
  },
  {
    pattern: /^PATH$/,
    severity: 'high',
    description: 'Overriding PATH can redirect system binary execution to attacker-controlled programs',
  },
  {
    pattern: /^NODE_OPTIONS$/,
    severity: 'high',
    description: 'NODE_OPTIONS can inject --require or --experimental flags that execute arbitrary code at Node.js startup',
  },
  {
    pattern: /^JAVA_TOOL_OPTIONS$/,
    severity: 'high',
    description: 'JAVA_TOOL_OPTIONS is automatically read by all JVM processes and can load malicious agents',
  },
  // Medium: language runtime injection
  {
    pattern: /^PYTHONSTARTUP$/,
    severity: 'medium',
    description: 'PYTHONSTARTUP executes an arbitrary Python file when the interpreter starts',
  },
  {
    pattern: /^PYTHONPATH$/,
    severity: 'medium',
    description: 'PYTHONPATH can inject malicious Python modules that shadow standard library imports',
  },
  {
    pattern: /^RUBYOPT$/,
    severity: 'medium',
    description: 'RUBYOPT passes options to every Ruby interpreter invocation, enabling code injection via -r',
  },
  {
    pattern: /^PERL5OPT$/,
    severity: 'medium',
    description: 'PERL5OPT is read by every Perl process and can load arbitrary modules via -M',
  },
  // Critical: credential and secret exposure
  {
    pattern: /^(?:AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN)$/,
    severity: 'critical',
    description: 'AWS credentials passed directly to MCP server environment -- use IAM roles or credential providers instead',
  },
  {
    pattern: /^(?:GOOGLE_APPLICATION_CREDENTIALS|GOOGLE_API_KEY)$/,
    severity: 'high',
    description: 'Google Cloud credentials exposed in MCP server environment -- use workload identity or service account impersonation',
  },
  {
    pattern: /^(?:AZURE_CLIENT_SECRET|AZURE_TENANT_ID)$/,
    severity: 'high',
    description: 'Azure credentials exposed in MCP server environment -- use managed identity instead',
  },
  // High: runtime behavior override
  {
    pattern: /^(?:HTTP_PROXY|HTTPS_PROXY|ALL_PROXY|NO_PROXY)$/i,
    severity: 'high',
    description: 'Proxy environment variable redirects all HTTP traffic through an attacker-controlled proxy (MITM risk)',
  },
  {
    pattern: /^(?:SSL_CERT_FILE|SSL_CERT_DIR|NODE_TLS_REJECT_UNAUTHORIZED|NODE_EXTRA_CA_CERTS)$/,
    severity: 'high',
    description: 'TLS certificate override can enable MITM attacks by trusting attacker-controlled certificates',
  },
  {
    pattern: /^GIT_SSH_COMMAND$/,
    severity: 'high',
    description: 'GIT_SSH_COMMAND overrides the SSH command used by git, enabling credential interception or code injection',
  },
  // Medium: language runtime and debug injection
  {
    pattern: /^(?:DOTNET_STARTUP_HOOKS|COR_ENABLE_PROFILING|CORECLR_ENABLE_PROFILING)$/,
    severity: 'medium',
    description: '.NET startup hooks or profiler injection can execute arbitrary code in the .NET runtime',
  },
  {
    pattern: /^(?:GOFLAGS|GOPATH)$/,
    severity: 'medium',
    description: 'Go environment override can inject build flags or redirect module loading',
  },
  // Critical: credential and secret exposure (additional cloud providers)
  {
    pattern: /^(?:ANTHROPIC_API_KEY|OPENAI_API_KEY|GEMINI_API_KEY|COHERE_API_KEY|HUGGING_FACE_TOKEN|HF_TOKEN)$/,
    severity: 'critical',
    description: 'AI/LLM provider API key passed directly to MCP server environment -- use credential managers or scoped tokens instead',
  },
  {
    pattern: /^(?:STRIPE_SECRET_KEY|STRIPE_API_KEY|TWILIO_AUTH_TOKEN|SENDGRID_API_KEY)$/,
    severity: 'critical',
    description: 'Payment/communication service secret key exposed in MCP server environment -- use scoped API keys with minimal permissions',
  },
  {
    pattern: /^(?:DATABASE_URL|DATABASE_PASSWORD|DB_PASSWORD|REDIS_PASSWORD|REDIS_URL|MONGODB_URI)$/,
    severity: 'critical',
    description: 'Database credentials passed directly to MCP server environment -- use IAM authentication or credential rotation',
  },
  {
    pattern: /^(?:GITHUB_TOKEN|GITLAB_TOKEN|BITBUCKET_TOKEN|GH_TOKEN)$/,
    severity: 'high',
    description: 'Source control token exposed in MCP server environment -- use fine-grained tokens with minimal repository access',
  },
  {
    pattern: /^(?:NPM_TOKEN|PYPI_TOKEN|NUGET_API_KEY|CARGO_REGISTRY_TOKEN)$/,
    severity: 'high',
    description: 'Package registry token exposed in MCP server environment -- enables supply chain attacks via unauthorized package publishing',
  },
  // High: debug and profiling exposure
  {
    pattern: /^(?:NODE_DEBUG|DEBUG|VERBOSE|TRACE)$/,
    severity: 'medium',
    description: 'Debug/verbose mode enabled in MCP server environment -- may leak sensitive data in log output',
  },
  {
    pattern: /^(?:ELECTRON_RUN_AS_NODE)$/,
    severity: 'high',
    description: 'ELECTRON_RUN_AS_NODE bypasses Electron sandboxing and enables arbitrary Node.js execution',
  },
  // Critical: MCP-specific credential exposure
  {
    pattern: /^(?:MCP_API_KEY|MCP_SECRET|MCP_AUTH_TOKEN|MCP_SERVER_TOKEN)$/,
    severity: 'critical',
    description: 'MCP server authentication token exposed in environment -- use secure credential stores instead',
  },
  {
    pattern: /^(?:CLAUDE_API_KEY|CLAUDE_SECRET_KEY|ANTHROPIC_AUTH_TOKEN)$/,
    severity: 'critical',
    description: 'Claude/Anthropic authentication credential passed directly to MCP server environment',
  },
  // High: additional cloud provider and AI credentials
  {
    pattern: /^(?:MISTRAL_API_KEY|TOGETHER_API_KEY|GROQ_API_KEY|REPLICATE_API_TOKEN|DEEPSEEK_API_KEY|XAI_API_KEY)$/,
    severity: 'critical',
    description: 'AI/LLM provider API key passed directly to MCP server environment -- use credential managers or scoped tokens instead',
  },
  {
    pattern: /^(?:VERCEL_TOKEN|NETLIFY_AUTH_TOKEN|HEROKU_API_KEY|FLY_ACCESS_TOKEN|RAILWAY_TOKEN)$/,
    severity: 'high',
    description: 'PaaS deployment token exposed in MCP server environment -- enables unauthorized deployments and infrastructure access',
  },
  {
    pattern: /^(?:DOCKER_PASSWORD|DOCKER_AUTH_CONFIG|DOCKER_TOKEN)$/,
    severity: 'high',
    description: 'Docker registry credentials exposed in MCP server environment -- enables supply chain attacks via unauthorized image publishing',
  },
  // Medium: debug and telemetry exposure
  {
    pattern: /^(?:OTEL_EXPORTER_OTLP_HEADERS|OTEL_EXPORTER_OTLP_ENDPOINT)$/,
    severity: 'medium',
    description: 'OpenTelemetry exporter configured in MCP server -- telemetry data may expose sensitive operation details to external endpoints',
  },
  // Critical: additional dangerous runtime overrides
  {
    pattern: /^(?:PYTHONHTTPSVERIFY|CURL_CA_BUNDLE|REQUESTS_CA_BUNDLE|GIT_SSL_NO_VERIFY)$/,
    severity: 'critical',
    description: 'TLS/SSL verification bypass configured in MCP server environment -- enables man-in-the-middle attacks',
  },
  // Critical: additional AI/LLM provider credentials (2026 additions)
  {
    pattern: /^(?:FIREWORKS_API_KEY|PERPLEXITY_API_KEY|CEREBRAS_API_KEY|SAMBANOVA_API_KEY|AI21_API_KEY|VOYAGE_API_KEY|ANYSCALE_API_KEY)$/,
    severity: 'critical',
    description: 'AI/LLM provider API key passed directly to MCP server environment -- use credential managers or scoped tokens instead',
  },
  {
    pattern: /^(?:PINECONE_API_KEY|WEAVIATE_API_KEY|QDRANT_API_KEY|CHROMA_API_KEY|MILVUS_TOKEN)$/,
    severity: 'critical',
    description: 'Vector database API key exposed in MCP server environment -- enables unauthorized access to RAG knowledge bases and embeddings',
  },
  // High: infrastructure and deployment credentials
  {
    pattern: /^(?:CLOUDFLARE_API_TOKEN|CLOUDFLARE_API_KEY|CF_API_TOKEN)$/,
    severity: 'critical',
    description: 'Cloudflare API credentials exposed in MCP server environment -- enables DNS hijacking, WAF bypass, and domain takeover',
  },
  {
    pattern: /^(?:TERRAFORM_TOKEN|TF_TOKEN_|PULUMI_ACCESS_TOKEN|VAULT_TOKEN)$/,
    severity: 'critical',
    description: 'Infrastructure-as-Code or secret manager token exposed in MCP server environment -- enables infrastructure manipulation and secret theft',
  },
  {
    pattern: /^(?:SLACK_BOT_TOKEN|SLACK_TOKEN|SLACK_WEBHOOK_URL|DISCORD_TOKEN|DISCORD_BOT_TOKEN|TELEGRAM_BOT_TOKEN)$/,
    severity: 'high',
    description: 'Messaging platform token exposed in MCP server environment -- enables unauthorized message sending, channel access, and data exfiltration',
  },
  {
    pattern: /^(?:SENTRY_DSN|SENTRY_AUTH_TOKEN|DATADOG_API_KEY|DD_API_KEY|NEW_RELIC_LICENSE_KEY)$/,
    severity: 'medium',
    description: 'Observability platform credentials exposed in MCP server environment -- enables telemetry data exfiltration and alert manipulation',
  },
  // Critical: container and orchestration credentials
  {
    pattern: /^(?:KUBECONFIG|KUBERNETES_SERVICE_TOKEN|K8S_TOKEN|KUBE_TOKEN)$/,
    severity: 'critical',
    description: 'Kubernetes credentials exposed in MCP server environment -- enables container deployment, secret access, and cluster compromise',
  },
  // High: additional runtime injection vectors
  {
    pattern: /^(?:RUBY_GC_HEAP_INIT_SLOTS|RUBY_GC_MALLOC_LIMIT)$/,
    severity: 'medium',
    description: 'Ruby GC tuning parameters in MCP server environment -- while not directly exploitable, unusual presence may indicate environment manipulation',
  },
  {
    pattern: /^(?:UV_THREADPOOL_SIZE|NODE_CLUSTER_SCHED_POLICY|UV_USE_IO_URING)$/,
    severity: 'medium',
    description: 'Node.js/libuv runtime internals overridden in MCP server environment -- may affect concurrency behavior and enable side-channel attacks',
  },
  // Critical: additional AI/ML and agent credentials (2026 Q2)
  {
    pattern: /^(?:GOOGLE_GENAI_API_KEY|GOOGLE_AI_API_KEY|GEMINI_API_KEY_2|VERTEX_AI_TOKEN)$/,
    severity: 'critical',
    description: 'Google AI/Gemini API key passed directly to MCP server environment -- use workload identity or service account impersonation instead',
  },
  {
    pattern: /^(?:CURSOR_API_KEY|WINDSURF_API_KEY|CLINE_API_KEY|CONTINUE_API_KEY)$/,
    severity: 'critical',
    description: 'IDE AI extension API key exposed in MCP server environment -- enables unauthorized access to the AI service and billing account',
  },
  {
    pattern: /^(?:MCP_PROXY_TOKEN|MCP_GATEWAY_SECRET|MCP_RELAY_KEY)$/,
    severity: 'critical',
    description: 'MCP proxy or gateway authentication token exposed in environment -- enables unauthorized access to MCP infrastructure',
  },
  {
    pattern: /^(?:SSH_AUTH_SOCK|SSH_AGENT_PID)$/,
    severity: 'critical',
    description: 'SSH agent socket exposed to MCP server environment -- enables unauthorized SSH key usage and remote server access',
  },
  {
    pattern: /^(?:SUPABASE_SERVICE_ROLE_KEY|SUPABASE_ANON_KEY|FIREBASE_TOKEN|FIREBASE_SERVICE_ACCOUNT)$/,
    severity: 'critical',
    description: 'Backend-as-a-Service credentials exposed in MCP server environment -- enables full database access and user impersonation',
  },
  {
    pattern: /^(?:DOPPLER_TOKEN|DOPPLER_PROJECT|INFISICAL_TOKEN|CHAMBER_KMS_KEY_ALIAS)$/,
    severity: 'critical',
    description: 'Secret management platform credentials exposed in MCP server environment -- enables access to all managed secrets',
  },
  // High: build and CI credentials
  {
    pattern: /^(?:CIRCLE_TOKEN|TRAVIS_TOKEN|BUILDKITE_AGENT_TOKEN|JENKINS_API_TOKEN|DRONE_TOKEN)$/,
    severity: 'high',
    description: 'CI/CD platform token exposed in MCP server environment -- enables unauthorized build triggers and pipeline manipulation',
  },
  {
    pattern: /^(?:SNYK_TOKEN|SONAR_TOKEN|CODECOV_TOKEN|COVERALLS_REPO_TOKEN)$/,
    severity: 'high',
    description: 'Code quality/security platform token exposed in MCP server environment -- enables tampering with security scan results',
  },
  // Critical: additional AI agent and MCP credentials (2026 Q2)
  {
    pattern: /^(?:GROK_API_KEY|COHERE_API_KEY_V2|LLAMA_API_KEY|CLAUDE_SESSION_KEY|OPENROUTER_API_KEY)$/,
    severity: 'critical',
    description: 'AI/LLM provider API key passed directly to MCP server environment -- use credential managers or scoped tokens instead',
  },
  {
    pattern: /^(?:MCP_SESSION_TOKEN|MCP_TRANSPORT_KEY|MCP_OAUTH_CLIENT_SECRET|MCP_SIGNING_KEY)$/,
    severity: 'critical',
    description: 'MCP transport or session credential exposed in environment -- enables session hijacking and unauthorized tool execution',
  },
  {
    pattern: /^(?:SNOWFLAKE_PASSWORD|BIGQUERY_KEY|REDSHIFT_PASSWORD|DATABRICKS_TOKEN)$/,
    severity: 'critical',
    description: 'Data warehouse credentials exposed in MCP server environment -- enables unauthorized access to business-critical analytics data',
  },
  {
    pattern: /^(?:DOCUSIGN_INTEGRATION_KEY|HELLOSIGN_API_KEY|PANDADOC_API_KEY)$/,
    severity: 'critical',
    description: 'Document signing platform credentials exposed in MCP server environment -- enables creation of fraudulent signature requests',
  },
  {
    pattern: /^(?:JIRA_API_TOKEN|LINEAR_API_KEY|ASANA_TOKEN|TRELLO_API_KEY|NOTION_API_KEY)$/,
    severity: 'high',
    description: 'Project management/wiki platform token exposed in MCP server environment -- enables unauthorized data access and content modification',
  },
  {
    pattern: /^(?:SALESFORCE_TOKEN|HUBSPOT_API_KEY|ZENDESK_TOKEN|INTERCOM_TOKEN)$/,
    severity: 'high',
    description: 'CRM platform credentials exposed in MCP server environment -- enables access to customer PII and business records',
  },
  {
    pattern: /^(?:NGROK_AUTHTOKEN|CLOUDFLARED_TOKEN|LOCALTUNNEL_TOKEN)$/,
    severity: 'high',
    description: 'Tunnel service authentication token exposed in MCP server environment -- enables unauthorized exposure of local services to the internet',
  },
  // 2026-04 additions: cryptocurrency, A2A, additional AI agent tokens
  {
    pattern: /^(?:WALLET_PRIVATE_KEY|ETH_PRIVATE_KEY|SOLANA_PRIVATE_KEY|MNEMONIC_PHRASE|SEED_PHRASE|CRYPTO_PRIVATE_KEY)$/,
    severity: 'critical',
    description: 'Cryptocurrency wallet private key or seed phrase exposed in MCP server environment -- enables immediate and irreversible theft of funds',
  },
  {
    pattern: /^(?:A2A_TOKEN|A2A_AUTH_KEY|AGENT_TO_AGENT_SECRET|A2A_API_KEY)$/,
    severity: 'critical',
    description: 'Agent-to-Agent (A2A) protocol credentials exposed in MCP server environment -- enables impersonation of trusted agents and cross-agent injection',
  },
  {
    pattern: /^(?:LANGCHAIN_API_KEY|LANGSMITH_API_KEY|LANGGRAPH_API_KEY|CREWAI_API_KEY|AUTOGEN_TOKEN)$/,
    severity: 'critical',
    description: 'AI agent framework API key exposed in MCP server environment -- enables unauthorized access to agent orchestration platforms and trace data',
  },
  {
    pattern: /^(?:TAVILY_API_KEY|SERPER_API_KEY|BRAVE_SEARCH_API_KEY|EXA_API_KEY|FIRECRAWL_API_KEY)$/,
    severity: 'high',
    description: 'AI search/scraping tool API key exposed in MCP server environment -- enables unauthorized web access and potential billing abuse',
  },
  {
    pattern: /^(?:NEON_API_KEY|PLANETSCALE_TOKEN|TURSO_AUTH_TOKEN|XATA_API_KEY|UPSTASH_REDIS_TOKEN)$/,
    severity: 'critical',
    description: 'Serverless database credentials exposed in MCP server environment -- enables unauthorized data access and potential data destruction',
  },
  {
    pattern: /^(?:RESEND_API_KEY|POSTMARK_SERVER_TOKEN|MAILGUN_API_KEY|SES_ACCESS_KEY)$/,
    severity: 'high',
    description: 'Email service credentials exposed in MCP server environment -- enables sending phishing emails and exfiltrating data via email (Postmark MCP incident pattern)',
  },
  {
    pattern: /^(?:R2_ACCESS_KEY|BACKBLAZE_KEY|WASABI_ACCESS_KEY|MINIO_SECRET_KEY)$/,
    severity: 'critical',
    description: 'Object storage credentials exposed in MCP server environment -- enables unauthorized access to stored files and potential data exfiltration',
  },
  {
    pattern: /^(?:MCP_INSPECTOR_PORT|MCP_INSPECTOR_HOST|MCP_DEBUG_PORT)$/,
    severity: 'medium',
    description: 'MCP Inspector/debug configuration exposed in MCP server environment -- may enable DNS rebinding or CSRF attacks against the inspector (CVE-2025-49596 pattern)',
  },
]

/**
 * Analyze MCP server environment variables for runtime hijacking risks.
 * Checks the server-level env map for dangerous variable names.
 */
export function analyzeSuspiciousEnv(server: MCPServer): Finding[] {
  if (!server.env || Object.keys(server.env).length === 0) return []

  const findings: Finding[] = []

  for (const [envVar, value] of Object.entries(server.env)) {
    for (const rule of ENV_RULES) {
      if (rule.pattern.test(envVar)) {
        findings.push({
          analyzer: 'suspicious-env',
          severity: rule.severity,
          server_name: server.name,
          tool_name: '',
          description: rule.description,
          field: `env.${envVar}`,
          evidence: `${envVar}=${value.slice(0, 60)}`,
          remediation: SUSPICIOUS_ENV_REMEDIATION,
        })
        break
      }
    }
  }

  return findings
}
