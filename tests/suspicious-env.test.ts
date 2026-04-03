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

  it('detects AI/LLM API keys as critical', () => {
    const s: MCPServer = {
      name: 'ai-server',
      command: 'node',
      args: [],
      env: { OPENAI_API_KEY: 'sk-test-12345' },
    }
    const findings = analyzeSuspiciousEnv(s)
    expect(findings).toHaveLength(1)
    expect(findings[0].severity).toBe('critical')
    expect(findings[0].description).toContain('AI/LLM provider')
  })

  it('detects database credentials as critical', () => {
    const s: MCPServer = {
      name: 'db-server',
      command: 'node',
      args: [],
      env: { DATABASE_URL: 'postgres://user:pass@host:5432/db' },
    }
    const findings = analyzeSuspiciousEnv(s)
    expect(findings).toHaveLength(1)
    expect(findings[0].severity).toBe('critical')
    expect(findings[0].description).toContain('Database credentials')
  })

  it('detects payment service keys as critical', () => {
    const s: MCPServer = {
      name: 'stripe-server',
      command: 'node',
      args: [],
      env: { STRIPE_SECRET_KEY: 'sk_test_12345' },
    }
    const findings = analyzeSuspiciousEnv(s)
    expect(findings).toHaveLength(1)
    expect(findings[0].severity).toBe('critical')
  })

  it('detects source control tokens as high', () => {
    const s: MCPServer = {
      name: 'git-server',
      command: 'node',
      args: [],
      env: { GITHUB_TOKEN: 'ghp_12345' },
    }
    const findings = analyzeSuspiciousEnv(s)
    expect(findings).toHaveLength(1)
    expect(findings[0].severity).toBe('high')
    expect(findings[0].description).toContain('Source control token')
  })

  it('detects package registry tokens as high', () => {
    const s: MCPServer = {
      name: 'npm-server',
      command: 'node',
      args: [],
      env: { NPM_TOKEN: 'npm_12345' },
    }
    const findings = analyzeSuspiciousEnv(s)
    expect(findings).toHaveLength(1)
    expect(findings[0].severity).toBe('high')
    expect(findings[0].description).toContain('Package registry token')
  })

  it('detects ELECTRON_RUN_AS_NODE as high', () => {
    const s: MCPServer = {
      name: 'electron-server',
      command: 'node',
      args: [],
      env: { ELECTRON_RUN_AS_NODE: '1' },
    }
    const findings = analyzeSuspiciousEnv(s)
    expect(findings).toHaveLength(1)
    expect(findings[0].severity).toBe('high')
    expect(findings[0].description).toContain('ELECTRON_RUN_AS_NODE')
  })

  it('detects MCP-specific auth tokens as critical', () => {
    const s: MCPServer = {
      name: 'mcp-auth',
      command: 'node',
      args: [],
      env: { MCP_API_KEY: 'mcp_12345' },
    }
    const findings = analyzeSuspiciousEnv(s)
    expect(findings).toHaveLength(1)
    expect(findings[0].severity).toBe('critical')
    expect(findings[0].description).toContain('MCP server authentication')
  })

  it('detects additional AI provider keys as critical', () => {
    const s: MCPServer = {
      name: 'ai-provider',
      command: 'node',
      args: [],
      env: { MISTRAL_API_KEY: 'mk-test-12345' },
    }
    const findings = analyzeSuspiciousEnv(s)
    expect(findings).toHaveLength(1)
    expect(findings[0].severity).toBe('critical')
    expect(findings[0].description).toContain('AI/LLM provider')
  })

  it('detects PaaS deployment tokens as high', () => {
    const s: MCPServer = {
      name: 'vercel-server',
      command: 'node',
      args: [],
      env: { VERCEL_TOKEN: 'vc_test_12345' },
    }
    const findings = analyzeSuspiciousEnv(s)
    expect(findings).toHaveLength(1)
    expect(findings[0].severity).toBe('high')
    expect(findings[0].description).toContain('PaaS deployment')
  })

  it('detects Docker registry credentials as high', () => {
    const s: MCPServer = {
      name: 'docker-server',
      command: 'node',
      args: [],
      env: { DOCKER_PASSWORD: 'secret123' },
    }
    const findings = analyzeSuspiciousEnv(s)
    expect(findings).toHaveLength(1)
    expect(findings[0].severity).toBe('high')
    expect(findings[0].description).toContain('Docker registry')
  })

  it('detects TLS verification bypass as critical', () => {
    const s: MCPServer = {
      name: 'no-verify',
      command: 'node',
      args: [],
      env: { GIT_SSL_NO_VERIFY: '1' },
    }
    const findings = analyzeSuspiciousEnv(s)
    expect(findings).toHaveLength(1)
    expect(findings[0].severity).toBe('critical')
    expect(findings[0].description).toContain('TLS/SSL verification bypass')
  })

  it('detects vector database API keys as critical', () => {
    const s: MCPServer = {
      name: 'vector-db',
      command: 'node',
      args: [],
      env: { PINECONE_API_KEY: 'pk-test-12345' },
    }
    const findings = analyzeSuspiciousEnv(s)
    expect(findings).toHaveLength(1)
    expect(findings[0].severity).toBe('critical')
    expect(findings[0].description).toContain('Vector database')
  })

  it('detects Cloudflare API token as critical', () => {
    const s: MCPServer = {
      name: 'cf-server',
      command: 'node',
      args: [],
      env: { CLOUDFLARE_API_TOKEN: 'cf-test-12345' },
    }
    const findings = analyzeSuspiciousEnv(s)
    expect(findings).toHaveLength(1)
    expect(findings[0].severity).toBe('critical')
    expect(findings[0].description).toContain('Cloudflare')
  })

  it('detects Kubernetes credentials as critical', () => {
    const s: MCPServer = {
      name: 'k8s-server',
      command: 'node',
      args: [],
      env: { KUBECONFIG: '/home/user/.kube/config' },
    }
    const findings = analyzeSuspiciousEnv(s)
    expect(findings).toHaveLength(1)
    expect(findings[0].severity).toBe('critical')
    expect(findings[0].description).toContain('Kubernetes')
  })

  it('detects Vault/IaC tokens as critical', () => {
    const s: MCPServer = {
      name: 'vault-server',
      command: 'node',
      args: [],
      env: { VAULT_TOKEN: 'hvs.test-12345' },
    }
    const findings = analyzeSuspiciousEnv(s)
    expect(findings).toHaveLength(1)
    expect(findings[0].severity).toBe('critical')
    expect(findings[0].description).toContain('Infrastructure')
  })

  it('detects Slack tokens as high', () => {
    const s: MCPServer = {
      name: 'slack-server',
      command: 'node',
      args: [],
      env: { SLACK_BOT_TOKEN: 'xoxb-test-12345' },
    }
    const findings = analyzeSuspiciousEnv(s)
    expect(findings).toHaveLength(1)
    expect(findings[0].severity).toBe('high')
    expect(findings[0].description).toContain('Messaging platform')
  })

  it('detects additional AI provider API keys as critical', () => {
    const s: MCPServer = {
      name: 'fireworks-server',
      command: 'node',
      args: [],
      env: { FIREWORKS_API_KEY: 'fw-test-12345' },
    }
    const findings = analyzeSuspiciousEnv(s)
    expect(findings).toHaveLength(1)
    expect(findings[0].severity).toBe('critical')
    expect(findings[0].description).toContain('AI/LLM provider')
  })

  it('detects observability platform credentials as medium', () => {
    const s: MCPServer = {
      name: 'dd-server',
      command: 'node',
      args: [],
      env: { DATADOG_API_KEY: 'dd-test-12345' },
    }
    const findings = analyzeSuspiciousEnv(s)
    expect(findings).toHaveLength(1)
    expect(findings[0].severity).toBe('medium')
    expect(findings[0].description).toContain('Observability')
  })

  it('detects SSH_AUTH_SOCK as critical', () => {
    const s: MCPServer = {
      name: 'ssh-server',
      command: 'node',
      args: [],
      env: { SSH_AUTH_SOCK: '/tmp/ssh-agent.sock' },
    }
    const findings = analyzeSuspiciousEnv(s)
    expect(findings).toHaveLength(1)
    expect(findings[0].severity).toBe('critical')
    expect(findings[0].description).toContain('SSH agent socket')
  })

  it('detects Supabase service role key as critical', () => {
    const s: MCPServer = {
      name: 'supabase-server',
      command: 'node',
      args: [],
      env: { SUPABASE_SERVICE_ROLE_KEY: 'eyJhbGciOiJIUzI1NiJ9.test' },
    }
    const findings = analyzeSuspiciousEnv(s)
    expect(findings).toHaveLength(1)
    expect(findings[0].severity).toBe('critical')
    expect(findings[0].description).toContain('Backend-as-a-Service')
  })

  it('detects Doppler token as critical', () => {
    const s: MCPServer = {
      name: 'doppler-server',
      command: 'node',
      args: [],
      env: { DOPPLER_TOKEN: 'dp.st.test_12345' },
    }
    const findings = analyzeSuspiciousEnv(s)
    expect(findings).toHaveLength(1)
    expect(findings[0].severity).toBe('critical')
    expect(findings[0].description).toContain('Secret management')
  })

  it('detects CI/CD platform tokens as high', () => {
    const s: MCPServer = {
      name: 'ci-server',
      command: 'node',
      args: [],
      env: { BUILDKITE_AGENT_TOKEN: 'bk-test-12345' },
    }
    const findings = analyzeSuspiciousEnv(s)
    expect(findings).toHaveLength(1)
    expect(findings[0].severity).toBe('high')
    expect(findings[0].description).toContain('CI/CD platform')
  })

  it('detects code quality platform tokens as high', () => {
    const s: MCPServer = {
      name: 'snyk-server',
      command: 'node',
      args: [],
      env: { SNYK_TOKEN: 'snyk-test-12345' },
    }
    const findings = analyzeSuspiciousEnv(s)
    expect(findings).toHaveLength(1)
    expect(findings[0].severity).toBe('high')
    expect(findings[0].description).toContain('Code quality')
  })

  it('detects MCP proxy token as critical', () => {
    const s: MCPServer = {
      name: 'mcp-proxy',
      command: 'node',
      args: [],
      env: { MCP_PROXY_TOKEN: 'proxy-test-12345' },
    }
    const findings = analyzeSuspiciousEnv(s)
    expect(findings).toHaveLength(1)
    expect(findings[0].severity).toBe('critical')
    expect(findings[0].description).toContain('MCP proxy')
  })

  it('detects IDE AI extension API keys as critical', () => {
    const s: MCPServer = {
      name: 'cursor-server',
      command: 'node',
      args: [],
      env: { CURSOR_API_KEY: 'cursor-test-12345' },
    }
    const findings = analyzeSuspiciousEnv(s)
    expect(findings).toHaveLength(1)
    expect(findings[0].severity).toBe('critical')
    expect(findings[0].description).toContain('IDE AI extension')
  })
})
