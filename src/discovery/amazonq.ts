import * as fs from 'fs'
import * as path from 'path'
import * as os from 'os'
import type { MCPConfig, MCPServer } from '../types.js'

/**
 * Amazon Q Developer stores MCP config in two possible filenames.
 * Check both and merge results (current format first, legacy fallback).
 */
const CONFIG_FILENAMES = ['default.json', 'mcp.json']

/** Base directory for Amazon Q config. */
function getAmazonQConfigDir(): string {
  const home = os.homedir()
  switch (process.platform) {
    case 'win32':
      return path.join(process.env.USERPROFILE || home, '.aws', 'amazonq')
    default:
      return path.join(home, '.aws', 'amazonq')
  }
}

/**
 * Discover MCP servers configured in Amazon Q Developer.
 * Checks both default.json (current) and mcp.json (legacy) in ~/.aws/amazonq/.
 * Deduplicates by server name.
 * Returns an empty array if no config files exist or cannot be parsed.
 */
export function discoverAmazonQServers(configPath?: string): MCPServer[] {
  if (configPath) {
    return parseAmazonQConfig(configPath)
  }

  const dir = getAmazonQConfigDir()
  const servers: MCPServer[] = []
  const seen = new Set<string>()

  for (const filename of CONFIG_FILENAMES) {
    const filePath = path.join(dir, filename)
    for (const s of parseAmazonQConfig(filePath)) {
      if (!seen.has(s.name)) {
        seen.add(s.name)
        servers.push(s)
      }
    }
  }

  return servers
}

function parseAmazonQConfig(filePath: string): MCPServer[] {
  if (!fs.existsSync(filePath)) return []
  try {
    const raw = fs.readFileSync(filePath, 'utf8')
    const config: MCPConfig = JSON.parse(raw)
    if (!config.mcpServers) return []
    return Object.entries(config.mcpServers).map(([name, def]) => ({
      name,
      ...def,
      source_client: 'amazonq' as const,
    }))
  } catch {
    return []
  }
}
