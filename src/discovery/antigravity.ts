import * as fs from 'fs'
import * as path from 'path'
import * as os from 'os'
import type { MCPConfig, MCPServer } from '../types.js'

/** Path to Google Antigravity MCP configuration. */
function getAntigravityConfigPath(): string {
  const home = os.homedir()
  switch (process.platform) {
    case 'win32':
      return path.join(process.env.USERPROFILE || home, '.gemini', 'antigravity', 'mcp_config.json')
    default:
      return path.join(home, '.gemini', 'antigravity', 'mcp_config.json')
  }
}

/**
 * Discover MCP servers configured in Google Antigravity IDE.
 * Uses the same mcpServers format as Claude Desktop (compatible).
 * Returns an empty array if the config file does not exist or cannot be parsed.
 */
export function discoverAntigravityServers(configPath?: string): MCPServer[] {
  const filePath = configPath || getAntigravityConfigPath()
  if (!fs.existsSync(filePath)) return []
  try {
    const raw = fs.readFileSync(filePath, 'utf8')
    const config: MCPConfig = JSON.parse(raw)
    if (!config.mcpServers) return []
    return Object.entries(config.mcpServers).map(([name, def]) => ({
      name,
      ...def,
      source_client: 'antigravity' as const,
    }))
  } catch {
    return []
  }
}
