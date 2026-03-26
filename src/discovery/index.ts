import type { MCPServer } from '../types.js'
import { discoverClaudeServers } from './claude.js'
import { discoverCursorServers } from './cursor.js'
import { discoverWindsurfServers } from './windsurf.js'
import { discoverVSCodeServers } from './vscode.js'
import { discoverGeminiServers } from './gemini.js'
import { discoverClineServers } from './cline.js'
import { discoverJetBrainsServers } from './jetbrains.js'
import { discoverContinueServers } from './continue.js'
import { discoverAntigravityServers } from './antigravity.js'
import { discoverZedServers } from './zed.js'
import { discoverAmazonQServers } from './amazonq.js'

/** All supported MCP client identifiers. */
export type ClientId =
  | 'claude' | 'cursor' | 'windsurf' | 'vscode' | 'gemini'
  | 'cline' | 'jetbrains' | 'continue' | 'antigravity' | 'zed' | 'amazonq'

/** All client IDs in discovery order. */
const ALL_CLIENTS: ClientId[] = [
  'claude', 'cursor', 'windsurf', 'vscode', 'gemini',
  'cline', 'jetbrains', 'continue', 'antigravity', 'zed', 'amazonq',
]

export interface DiscoveryOptions {
  /** Path to a specific config file to scan (bypasses auto-discovery). */
  configFile?: string
  /** Which client configs to discover from. Default: all supported. */
  clients?: ClientId[]
}

/**
 * Discover all MCP servers from supported client configurations.
 * Deduplicates servers with the same name across clients.
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

  const clients = opts.clients ?? ALL_CLIENTS

  /** Map client ID to its discovery function. */
  const discoverers: Record<ClientId, () => MCPServer[]> = {
    claude:       discoverClaudeServers,
    cursor:       discoverCursorServers,
    windsurf:     discoverWindsurfServers,
    vscode:       discoverVSCodeServers,
    gemini:       discoverGeminiServers,
    cline:        discoverClineServers,
    jetbrains:    discoverJetBrainsServers,
    continue:     discoverContinueServers,
    antigravity:  discoverAntigravityServers,
    zed:          discoverZedServers,
    amazonq:      discoverAmazonQServers,
  }

  for (const client of clients) {
    const discover = discoverers[client]
    if (!discover) continue
    const discovered = discover()

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
