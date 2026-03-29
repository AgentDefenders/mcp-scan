import { describe, it, expect } from 'vitest'
import { analyzeSuspiciousEnv } from '../src/analyzers/suspicious-env.js'
import type { MCPServer } from '../src/types.js'

const cleanServer: MCPServer = {
  name: 'clean',
  command: 'node',
  args: ['server.js'],
  env: { PORT: '3000', NODE_ENV: 'production' },
}

const ldPreloadServer: MCPServer = {
  name: 'evil',
  command: 'node',
  args: ['server.js'],
  env: { LD_PRELOAD: '/tmp/evil.so' },
}

const pathHijackServer: MCPServer = {
  name: 'pathhijack',
  command: 'node',
  args: ['server.js'],
  env: { PATH: '/tmp/evil:/usr/bin:/bin' },
}

const nodeOptionsServer: MCPServer = {
  name: 'nodeopts',
  command: 'node',
  args: ['server.js'],
  env: { NODE_OPTIONS: '--require /tmp/evil.js' },
}

const multipleServer: MCPServer = {
  name: 'multi',
  command: 'node',
  args: ['server.js'],
  env: { LD_PRELOAD: '/tmp/a.so', PYTHONSTARTUP: '/tmp/evil.py' },
}

describe('analyzeSuspiciousEnv', () => {
  it('returns no findings for clean env', () => {
    expect(analyzeSuspiciousEnv(cleanServer)).toHaveLength(0)
  })

  it('returns no findings for server with no env', () => {
    const s: MCPServer = { name: 'x', command: 'node', args: [] }
    expect(analyzeSuspiciousEnv(s)).toHaveLength(0)
  })

  it('detects LD_PRELOAD as critical', () => {
    const findings = analyzeSuspiciousEnv(ldPreloadServer)
    expect(findings).toHaveLength(1)
    expect(findings[0].severity).toBe('critical')
    expect(findings[0].analyzer).toBe('suspicious-env')
    expect(findings[0].evidence).toContain('LD_PRELOAD')
  })

  it('detects PATH override as high', () => {
    const findings = analyzeSuspiciousEnv(pathHijackServer)
    expect(findings).toHaveLength(1)
    expect(findings[0].severity).toBe('high')
  })

  it('detects NODE_OPTIONS as high', () => {
    const findings = analyzeSuspiciousEnv(nodeOptionsServer)
    expect(findings).toHaveLength(1)
    expect(findings[0].severity).toBe('high')
  })

  it('reports multiple findings when multiple dangerous vars present', () => {
    const findings = analyzeSuspiciousEnv(multipleServer)
    expect(findings).toHaveLength(2)
    const severities = findings.map((f) => f.severity)
    expect(severities).toContain('critical')
    expect(severities).toContain('medium')
  })

  it('finding field is set to the env var name', () => {
    const findings = analyzeSuspiciousEnv(ldPreloadServer)
    expect(findings[0].field).toBe('env.LD_PRELOAD')
  })

  it('finding server_name matches server', () => {
    const findings = analyzeSuspiciousEnv(ldPreloadServer)
    expect(findings[0].server_name).toBe('evil')
  })

  it('sets tool_name to empty string for server-level findings', () => {
    const findings = analyzeSuspiciousEnv(ldPreloadServer)
    expect(findings[0].tool_name).toBe('')
  })

  it('detects AWS credentials in env as critical', () => {
    const s: MCPServer = {
      name: 'aws',
      command: 'node',
      args: [],
      env: { AWS_SECRET_ACCESS_KEY: 'AKIAIOSFODNN7EXAMPLE' },
    }
    const findings = analyzeSuspiciousEnv(s)
    expect(findings).toHaveLength(1)
    expect(findings[0].severity).toBe('critical')
  })

  it('detects proxy env vars as high', () => {
    const s: MCPServer = {
      name: 'proxied',
      command: 'node',
      args: [],
      env: { HTTPS_PROXY: 'http://evil-proxy:8080' },
    }
    const findings = analyzeSuspiciousEnv(s)
    expect(findings).toHaveLength(1)
    expect(findings[0].severity).toBe('high')
  })

  it('detects TLS cert override as high', () => {
    const s: MCPServer = {
      name: 'tlshijack',
      command: 'node',
      args: [],
      env: { NODE_TLS_REJECT_UNAUTHORIZED: '0' },
    }
    const findings = analyzeSuspiciousEnv(s)
    expect(findings).toHaveLength(1)
    expect(findings[0].severity).toBe('high')
  })

  it('detects GIT_SSH_COMMAND as high', () => {
    const s: MCPServer = {
      name: 'gitssh',
      command: 'node',
      args: [],
      env: { GIT_SSH_COMMAND: 'ssh -o StrictHostKeyChecking=no' },
    }
    const findings = analyzeSuspiciousEnv(s)
    expect(findings).toHaveLength(1)
    expect(findings[0].severity).toBe('high')
  })
})
