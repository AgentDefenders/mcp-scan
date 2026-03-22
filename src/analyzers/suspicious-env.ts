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
