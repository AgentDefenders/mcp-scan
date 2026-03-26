import * as fs from 'fs'
import * as path from 'path'
import * as os from 'os'
import type { MCPConfig, MCPServer } from '../types.js'

/**
 * VS Code variant directory names where Cline extension stores its config.
 * Cline (saoudrizwan.claude-dev) stores MCP settings in the globalStorage
 * directory of whichever VS Code variant the user has installed.
 */
const VSCODE_VARIANTS = ['Code', 'Code - Insiders', 'VSCodium']

/** Cline MCP settings filename within the globalStorage directory. */
const CLINE_SETTINGS_FILE = path.join(
  'globalStorage', 'saoudrizwan.claude-dev', 'settings', 'cline_mcp_settings.json'
)

/** Build candidate config paths for Cline across all VS Code variants. */
function getClineConfigPaths(): string[] {
  const home = os.homedir()
  const paths: string[] = []
  for (const variant of VSCODE_VARIANTS) {
    switch (process.platform) {
      case 'darwin':
        paths.push(path.join(home, 'Library', 'Application Support', variant, 'User', CLINE_SETTINGS_FILE))
        break
      case 'win32':
        paths.push(path.join(process.env.APPDATA || home, variant, 'User', CLINE_SETTINGS_FILE))
        break
      default:
        paths.push(path.join(home, '.config', variant, 'User', CLINE_SETTINGS_FILE))
    }
  }
  return paths
}

/**
 * Discover MCP servers configured in Cline (VS Code extension).
 * Checks all VS Code variants (Code, Code - Insiders, VSCodium).
 * Returns an empty array if no config file exists or cannot be parsed.
 */
export function discoverClineServers(configPath?: string): MCPServer[] {
  const paths = configPath ? [configPath] : getClineConfigPaths()
  const servers: MCPServer[] = []
  const seen = new Set<string>()

  for (const filePath of paths) {
    if (!fs.existsSync(filePath)) continue
    try {
      const raw = fs.readFileSync(filePath, 'utf8')
      const config: MCPConfig = JSON.parse(raw)
      if (!config.mcpServers) continue
      for (const [name, def] of Object.entries(config.mcpServers)) {
        if (!seen.has(name)) {
          seen.add(name)
          servers.push({ name, ...def, source_client: 'cline' as const })
        }
      }
    } catch {
      // Invalid JSON or read error -- skip this variant.
    }
  }

  return servers
}
