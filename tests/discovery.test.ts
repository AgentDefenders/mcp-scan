import * as fs from 'fs'
import * as os from 'os'
import * as path from 'path'
import { describe, it, expect } from 'vitest'
import { discoverWindsurfServers } from '../src/discovery/windsurf.js'
import { discoverVSCodeServers } from '../src/discovery/vscode.js'

function withTempConfig(content: object, fn: (p: string) => void): void {
  const tmpFile = path.join(os.tmpdir(), `mcp-scan-test-${Date.now()}.json`)
  fs.writeFileSync(tmpFile, JSON.stringify(content))
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
