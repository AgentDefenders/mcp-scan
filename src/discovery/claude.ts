import * as fs from 'fs'
import * as path from 'path'
import * as os from 'os'
import type { MCPConfig, MCPServer } from '../types.js'

/** Path to Claude Desktop MCP configuration on each platform. */
function getClaudeConfigPath(): string {
  const home = os.homedir()
  switch (process.platform) {
    case 'darwin':
      return path.join(home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json')
    case 'win32':
      return path.join(process.env.APPDATA || home, 'Claude', 'claude_desktop_config.json')
    default:
      return path.join(home, '.config', 'claude', 'claude_desktop_config.json')
  }
}

/**
 * Discover MCP servers configured in Claude Desktop.
 * Returns an empty array if the config file does not exist or cannot be parsed.
 */
export function discoverClaudeServers(configPath?: string): MCPServer[] {
  const filePath = configPath || getClaudeConfigPath()
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
