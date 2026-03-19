import * as fs from 'fs'
import * as path from 'path'
import * as os from 'os'
import type { MCPConfig, MCPServer } from '../types.js'

/** Path to VS Code global MCP configuration (VS Code 1.99+). */
function getVSCodeConfigPath(): string {
  const home = os.homedir()
  switch (process.platform) {
    case 'darwin':
      return path.join(home, 'Library', 'Application Support', 'Code', 'User', 'mcp.json')
    case 'linux':
      return path.join(home, '.config', 'Code', 'User', 'mcp.json')
    case 'win32':
      return path.join(process.env.APPDATA || home, 'Code', 'User', 'mcp.json')
    default:
      return path.join(home, '.config', 'Code', 'User', 'mcp.json')
  }
}

/**
 * Discover MCP servers configured in VS Code (1.99+).
 * Returns an empty array if the config file does not exist or cannot be parsed.
 */
export function discoverVSCodeServers(configPath?: string): MCPServer[] {
  const filePath = configPath || getVSCodeConfigPath()
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
    }))
  } catch {
    return []
  }
}
