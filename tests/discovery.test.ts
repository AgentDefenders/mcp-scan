import * as fs from 'fs'
import * as os from 'os'
import * as path from 'path'
import { describe, it, expect } from 'vitest'
import { discoverWindsurfServers } from '../src/discovery/windsurf.js'
import { discoverVSCodeServers } from '../src/discovery/vscode.js'
import { discoverGeminiServers } from '../src/discovery/gemini.js'
import { discoverClineServers } from '../src/discovery/cline.js'
import { discoverJetBrainsServers } from '../src/discovery/jetbrains.js'
import { discoverAntigravityServers } from '../src/discovery/antigravity.js'
import { discoverZedServers } from '../src/discovery/zed.js'
import { discoverAmazonQServers } from '../src/discovery/amazonq.js'
import { discoverContinueServers } from '../src/discovery/continue.js'

function withTempConfig(content: object, fn: (p: string) => void): void {
  const tmpFile = path.join(os.tmpdir(), `mcp-scan-test-${Date.now()}.json`)
  fs.writeFileSync(tmpFile, JSON.stringify(content))
  try {
    fn(tmpFile)
  } finally {
    fs.unlinkSync(tmpFile)
  }
}

function withTempFile(content: string, ext: string, fn: (p: string) => void): void {
  const tmpFile = path.join(os.tmpdir(), `mcp-scan-test-${Date.now()}.${ext}`)
  fs.writeFileSync(tmpFile, content)
  try {
    fn(tmpFile)
  } finally {
    fs.unlinkSync(tmpFile)
  }
}

describe('discoverWindsurfServers', () => {
  it('returns empty array when file does not exist', () => {
    expect(discoverWindsurfServers('/nonexistent/path/mcp.json')).toEqual([])
  })

  it('returns empty array for invalid JSON', () => {
    const tmpFile = path.join(os.tmpdir(), `mcp-bad-${Date.now()}.json`)
    fs.writeFileSync(tmpFile, 'NOT JSON')
    try {
      expect(discoverWindsurfServers(tmpFile)).toEqual([])
    } finally {
      fs.unlinkSync(tmpFile)
    }
  })

  it('returns empty array when mcpServers key is absent', () => {
    withTempConfig({}, (p) => {
      expect(discoverWindsurfServers(p)).toEqual([])
    })
  })

  it('parses mcpServers and returns server list', () => {
    withTempConfig({
      mcpServers: {
        'my-tool': { command: 'node', args: ['server.js'] },
        'other-tool': { command: 'python', args: ['-m', 'server'] },
      },
    }, (p) => {
      const servers = discoverWindsurfServers(p)
      expect(servers).toHaveLength(2)
      expect(servers[0].name).toBe('my-tool')
      expect(servers[0].command).toBe('node')
      expect(servers[1].name).toBe('other-tool')
    })
  })
})

describe('discoverVSCodeServers', () => {
  it('returns empty array when file does not exist', () => {
    expect(discoverVSCodeServers('/nonexistent/path/mcp.json')).toEqual([])
  })

  it('returns empty array for invalid JSON', () => {
    const tmpFile = path.join(os.tmpdir(), `mcp-vscode-bad-${Date.now()}.json`)
    fs.writeFileSync(tmpFile, '{ broken json')
    try {
      expect(discoverVSCodeServers(tmpFile)).toEqual([])
    } finally {
      fs.unlinkSync(tmpFile)
    }
  })

  it('returns empty array when mcpServers key is absent', () => {
    withTempConfig({}, (p) => {
      expect(discoverVSCodeServers(p)).toEqual([])
    })
  })

  it('parses mcpServers and returns server list', () => {
    withTempConfig({
      mcpServers: {
        'github': { command: 'npx', args: ['-y', '@modelcontextprotocol/server-github'] },
      },
    }, (p) => {
      const servers = discoverVSCodeServers(p)
      expect(servers).toHaveLength(1)
      expect(servers[0].name).toBe('github')
      expect(servers[0].command).toBe('npx')
    })
  })
})

describe('discoverGeminiServers', () => {
  it('returns servers when config exists with mcpServers', () => {
    withTempConfig({
      mcpServers: {
        'my-tool': { command: 'node', args: ['server.js'] },
        'other-tool': { command: 'python', args: ['-m', 'server'] },
      },
    }, (p) => {
      const servers = discoverGeminiServers(p)
      expect(servers).toHaveLength(2)
      expect(servers[0].name).toBe('my-tool')
      expect(servers[0].command).toBe('node')
      expect(servers[1].name).toBe('other-tool')
    })
  })

  it('returns empty array when mcpServers is empty object', () => {
    withTempConfig({ mcpServers: {} }, (p) => {
      expect(discoverGeminiServers(p)).toEqual([])
    })
  })

  it('returns empty array for malformed JSON', () => {
    const tmpFile = path.join(os.tmpdir(), `mcp-gemini-bad-${Date.now()}.json`)
    fs.writeFileSync(tmpFile, 'NOT JSON')
    try {
      expect(discoverGeminiServers(tmpFile)).toEqual([])
    } finally {
      fs.unlinkSync(tmpFile)
    }
  })

  it('returns empty array when mcpServers key is missing', () => {
    withTempConfig({}, (p) => {
      expect(discoverGeminiServers(p)).toEqual([])
    })
  })
})

describe('discoverClineServers', () => {
  it('returns empty array when file does not exist', () => {
    expect(discoverClineServers('/nonexistent/path/cline.json')).toEqual([])
  })

  it('returns empty array for invalid JSON', () => {
    withTempFile('NOT JSON', 'json', (p) => {
      expect(discoverClineServers(p)).toEqual([])
    })
  })

  it('returns empty array when mcpServers key is absent', () => {
    withTempConfig({}, (p) => {
      expect(discoverClineServers(p)).toEqual([])
    })
  })

  it('parses mcpServers and returns server list', () => {
    withTempConfig({
      mcpServers: {
        'fs-server': { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem'] },
      },
    }, (p) => {
      const servers = discoverClineServers(p)
      expect(servers).toHaveLength(1)
      expect(servers[0].name).toBe('fs-server')
      expect(servers[0].source_client).toBe('cline')
    })
  })
})

describe('discoverJetBrainsServers', () => {
  it('returns empty array when file does not exist', () => {
    expect(discoverJetBrainsServers('/nonexistent/path/mcp.json')).toEqual([])
  })

  it('returns empty array for invalid JSON', () => {
    withTempFile('{ broken', 'json', (p) => {
      expect(discoverJetBrainsServers(p)).toEqual([])
    })
  })

  it('parses mcpServers and returns server list', () => {
    withTempConfig({
      mcpServers: {
        'jb-tool': { command: 'node', args: ['server.js'] },
      },
    }, (p) => {
      const servers = discoverJetBrainsServers(p)
      expect(servers).toHaveLength(1)
      expect(servers[0].name).toBe('jb-tool')
      expect(servers[0].source_client).toBe('jetbrains')
    })
  })
})

describe('discoverAntigravityServers', () => {
  it('returns empty array when file does not exist', () => {
    expect(discoverAntigravityServers('/nonexistent/path/mcp.json')).toEqual([])
  })

  it('returns empty array for invalid JSON', () => {
    withTempFile('NOT JSON', 'json', (p) => {
      expect(discoverAntigravityServers(p)).toEqual([])
    })
  })

  it('returns empty array when mcpServers key is absent', () => {
    withTempConfig({}, (p) => {
      expect(discoverAntigravityServers(p)).toEqual([])
    })
  })

  it('parses mcpServers and returns server list', () => {
    withTempConfig({
      mcpServers: {
        'ag-tool': { command: 'python', args: ['-m', 'server'] },
      },
    }, (p) => {
      const servers = discoverAntigravityServers(p)
      expect(servers).toHaveLength(1)
      expect(servers[0].name).toBe('ag-tool')
      expect(servers[0].source_client).toBe('antigravity')
    })
  })
})

describe('discoverZedServers', () => {
  it('returns empty array when file does not exist', () => {
    expect(discoverZedServers('/nonexistent/path/settings.json')).toEqual([])
  })

  it('returns empty array for invalid JSON', () => {
    withTempFile('NOT JSON', 'json', (p) => {
      expect(discoverZedServers(p)).toEqual([])
    })
  })

  it('returns empty array when context_servers key is absent', () => {
    withTempConfig({}, (p) => {
      expect(discoverZedServers(p)).toEqual([])
    })
  })

  it('parses context_servers key and returns server list', () => {
    withTempFile(JSON.stringify({
      context_servers: {
        'zed-mcp': { command: 'node', args: ['zed-server.js'] },
        'zed-db': { command: 'npx', args: ['db-mcp'] },
      },
    }), 'json', (p) => {
      const servers = discoverZedServers(p)
      expect(servers).toHaveLength(2)
      expect(servers[0].name).toBe('zed-mcp')
      expect(servers[0].command).toBe('node')
      expect(servers[0].source_client).toBe('zed')
      expect(servers[1].name).toBe('zed-db')
    })
  })
})

describe('discoverAmazonQServers', () => {
  it('returns empty array when file does not exist', () => {
    expect(discoverAmazonQServers('/nonexistent/path/default.json')).toEqual([])
  })

  it('returns empty array for invalid JSON', () => {
    withTempFile('{ broken', 'json', (p) => {
      expect(discoverAmazonQServers(p)).toEqual([])
    })
  })

  it('returns empty array when mcpServers key is absent', () => {
    withTempConfig({}, (p) => {
      expect(discoverAmazonQServers(p)).toEqual([])
    })
  })

  it('parses mcpServers and returns server list', () => {
    withTempConfig({
      mcpServers: {
        'q-tool': { command: 'npx', args: ['q-mcp'] },
      },
    }, (p) => {
      const servers = discoverAmazonQServers(p)
      expect(servers).toHaveLength(1)
      expect(servers[0].name).toBe('q-tool')
      expect(servers[0].source_client).toBe('amazonq')
    })
  })
})

describe('discoverContinueServers', () => {
  it('returns empty array when file does not exist', () => {
    expect(discoverContinueServers('/nonexistent/path/config.yaml')).toEqual([])
  })

  it('parses YAML array format with mcpServers', () => {
    const yamlContent = `mcpServers:
  - name: continue-tool
    command: node
    args:
      - server.js
  - name: continue-db
    command: python
    args:
      - -m
      - db_server
`
    withTempFile(yamlContent, 'yaml', (p) => {
      const servers = discoverContinueServers(p)
      expect(servers).toHaveLength(2)
      expect(servers[0].name).toBe('continue-tool')
      expect(servers[0].command).toBe('node')
      expect(servers[0].source_client).toBe('continue')
      expect(servers[1].name).toBe('continue-db')
    })
  })

  it('returns empty array for invalid YAML', () => {
    withTempFile('{{{{invalid yaml', 'yaml', (p) => {
      expect(discoverContinueServers(p)).toEqual([])
    })
  })

  it('returns empty array when mcpServers key is absent in YAML', () => {
    withTempFile('models:\n  - name: gpt-4\n', 'yaml', (p) => {
      expect(discoverContinueServers(p)).toEqual([])
    })
  })
})
