import type { MCPServer } from '../types.js'
import { discoverClaudeServers } from './claude.js'
import { discoverCursorServers } from './cursor.js'

export interface DiscoveryOptions {
  /** Path to a specific config file to scan (bypasses auto-discovery). */
  configFile?: string
  /** Which client configs to discover from. Default: all supported. */
  clients?: ('claude' | 'cursor')[]
}

/**
 * Discover all MCP servers from supported client configurations.
 * Deduplicates servers with the same name.
 */
export function discoverAllServers(opts: DiscoveryOptions = {}): MCPServer[] {
  const servers: MCPServer[] = []
  const seen = new Set<string>()

  if (opts.configFile) {
    // Single file mode: treat as Claude Desktop config format.
    const discovered = discoverClaudeServers(opts.configFile)
    for (const s of discovered) {
      if (!seen.has(s.name)) {
        seen.add(s.name)
        servers.push(s)
      }
    }
    return servers
  }

  const clients = opts.clients ?? ['claude', 'cursor']

  for (const client of clients) {
    let discovered: MCPServer[] = []
    if (client === 'claude') discovered = discoverClaudeServers()
    if (client === 'cursor') discovered = discoverCursorServers()

    for (const s of discovered) {
      const key = `${client}:${s.name}`
      if (!seen.has(key)) {
        seen.add(key)
        servers.push({ ...s, name: s.name })
      }
    }
  }

  return servers
}
