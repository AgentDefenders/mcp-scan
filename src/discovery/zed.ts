import * as fs from 'fs'
import * as path from 'path'
import * as os from 'os'
import type { MCPServer } from '../types.js'

/** Path to Zed editor settings file. */
function getZedConfigPath(): string {
  const home = os.homedir()
  switch (process.platform) {
    case 'darwin':
      return path.join(home, '.zed', 'settings.json')
    case 'win32':
      return path.join(process.env.APPDATA || home, 'Zed', 'settings.json')
    default:
      return path.join(home, '.config', 'zed', 'settings.json')
  }
}

/**
 * Zed settings structure for MCP servers.
 * Zed uses `context_servers` instead of `mcpServers`.
 */
interface ZedConfig {
  context_servers?: Record<string, ZedServerDef>
}

interface ZedServerDef {
  command?: string
  args?: string[]
  env?: Record<string, string>
  settings?: Record<string, unknown>
}

/**
 * Discover MCP servers configured in Zed editor.
 * Zed uses a different key (`context_servers`) embedded in its main settings file.
 * Returns an empty array if the config file does not exist or cannot be parsed.
 */
export function discoverZedServers(configPath?: string): MCPServer[] {
  const filePath = configPath || getZedConfigPath()
  if (!fs.existsSync(filePath)) return []
  try {
    const raw = fs.readFileSync(filePath, 'utf8')
    const config: ZedConfig = JSON.parse(raw)
    if (!config.context_servers) return []
    return Object.entries(config.context_servers).map(([name, def]) => ({
      name,
      command: def.command,
      args: def.args,
      env: def.env,
      source_client: 'zed' as const,
    }))
  } catch {
    return []
  }
}
