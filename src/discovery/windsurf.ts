import * as fs from 'fs'
import * as path from 'path'
import * as os from 'os'
import type { MCPConfig, MCPServer } from '../types.js'

/** Path to Windsurf global MCP configuration. */
function getWindsurfConfigPath(): string {
  const home = os.homedir()
  switch (process.platform) {
    case 'darwin':
    case 'linux':
      return path.join(home, '.windsurf', 'mcp.json')
    case 'win32':
      return path.join(process.env.APPDATA || home, 'Windsurf', 'mcp.json')
    default:
      return path.join(home, '.windsurf', 'mcp.json')
  }
}

/**
 * Discover MCP servers configured in Windsurf.
 * Returns an empty array if the config file does not exist or cannot be parsed.
 */
export function discoverWindsurfServers(configPath?: string): MCPServer[] {
  const filePath = configPath || getWindsurfConfigPath()
  if (!fs.existsSync(filePath)) {
    return []
  }
  try {
    const raw = fs.readFileSync(filePath, 'utf8')
    const config: MCPConfig = JSON.parse(raw)
    if (!config.mcpServers) return []
    return Object.entries(config.mcpServers).map(([name, def]) => ({
      name,
      ...def,
      source_client: 'windsurf' as const,
    }))
  } catch {
    return []
  }
}
