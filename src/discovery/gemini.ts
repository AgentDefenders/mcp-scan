import * as fs from 'fs'
import * as path from 'path'
import * as os from 'os'
import type { MCPConfig, MCPServer } from '../types.js'

/** Path to Gemini CLI global MCP configuration. */
function getGeminiConfigPath(): string {
  const home = os.homedir()
  switch (process.platform) {
    case 'darwin':
    case 'linux':
      return path.join(home, '.gemini', 'settings.json')
    case 'win32':
      return path.join(process.env.APPDATA || home, 'Gemini', 'settings.json')
    default:
      return path.join(home, '.gemini', 'settings.json')
  }
}

/**
 * Discover MCP servers configured in Gemini CLI.
 * Returns an empty array if the config file does not exist or cannot be parsed.
 */
export function discoverGeminiServers(configPath?: string): MCPServer[] {
  const filePath = configPath || getGeminiConfigPath()
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
      source_client: 'gemini' as const,
    }))
  } catch {
    return []
  }
}
