import * as fs from 'fs'
import * as path from 'path'
import * as os from 'os'
import type { MCPConfig, MCPServer } from '../types.js'

/**
 * Discover MCP servers configured in JetBrains IDEs via Junie.
 * Checks two locations:
 *   1. User-level: ~/.junie/mcp/mcp.json
 *   2. Project-level: .junie/mcp/mcp.json (relative to cwd)
 * Deduplicates by server name (user-level wins on conflict).
 * Returns an empty array if no config files exist or cannot be parsed.
 */
export function discoverJetBrainsServers(configPath?: string): MCPServer[] {
  if (configPath) {
    return parseJunieConfig(configPath)
  }

  const servers: MCPServer[] = []
  const seen = new Set<string>()

  // User-level config.
  const userPath = path.join(os.homedir(), '.junie', 'mcp', 'mcp.json')
  for (const s of parseJunieConfig(userPath)) {
    if (!seen.has(s.name)) {
      seen.add(s.name)
      servers.push(s)
    }
  }

  // Project-level config.
  const projectPath = path.join(process.cwd(), '.junie', 'mcp', 'mcp.json')
  for (const s of parseJunieConfig(projectPath)) {
    if (!seen.has(s.name)) {
      seen.add(s.name)
      servers.push(s)
    }
  }

  return servers
}

function parseJunieConfig(filePath: string): MCPServer[] {
  if (!fs.existsSync(filePath)) return []
  try {
    const raw = fs.readFileSync(filePath, 'utf8')
    const config: MCPConfig = JSON.parse(raw)
    if (!config.mcpServers) return []
    return Object.entries(config.mcpServers).map(([name, def]) => ({
      name,
      ...def,
      source_client: 'jetbrains' as const,
    }))
  } catch {
    return []
  }
}
