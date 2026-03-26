import * as fs from 'fs'
import * as path from 'path'
import * as os from 'os'
import type { MCPServer } from '../types.js'

/**
 * Continue.dev MCP server definition (YAML array format).
 * Unlike other clients, Continue uses an array of objects, not a keyed object.
 */
interface ContinueServerDef {
  name: string
  command?: string
  args?: string[]
  env?: Record<string, string>
}

/** Base directory for Continue.dev config. */
function getContinueConfigDir(): string {
  const home = os.homedir()
  switch (process.platform) {
    case 'win32':
      return path.join(process.env.USERPROFILE || home, '.continue')
    default:
      return path.join(home, '.continue')
  }
}

/**
 * Discover MCP servers configured in Continue.dev.
 *
 * Continue stores MCP config in two possible locations:
 * 1. ~/.continue/config.yaml (mcpServers as a YAML array)
 * 2. ~/.continue/mcpServers/*.json (individual server JSON files, Claude Desktop format)
 *
 * Requires js-yaml for YAML parsing. Falls back gracefully if not available.
 * Returns an empty array if no config exists or cannot be parsed.
 */
export function discoverContinueServers(configPath?: string): MCPServer[] {
  const servers: MCPServer[] = []
  const seen = new Set<string>()

  if (configPath) {
    for (const s of parseContinueConfig(configPath)) {
      if (!seen.has(s.name)) {
        seen.add(s.name)
        servers.push(s)
      }
    }
    return servers
  }

  const dir = getContinueConfigDir()

  // Try config.yaml first.
  const yamlPath = path.join(dir, 'config.yaml')
  for (const s of parseContinueConfig(yamlPath)) {
    if (!seen.has(s.name)) {
      seen.add(s.name)
      servers.push(s)
    }
  }

  // Also check mcpServers/ directory for individual JSON files (Claude Desktop format).
  const mcpDir = path.join(dir, 'mcpServers')
  if (fs.existsSync(mcpDir)) {
    try {
      const files = fs.readdirSync(mcpDir).filter((f) => f.endsWith('.json'))
      for (const file of files) {
        try {
          const raw = fs.readFileSync(path.join(mcpDir, file), 'utf8')
          const config = JSON.parse(raw)
          if (config.mcpServers && typeof config.mcpServers === 'object') {
            for (const [name, def] of Object.entries(config.mcpServers)) {
              if (!seen.has(name)) {
                seen.add(name)
                servers.push({ name, ...(def as Omit<MCPServer, 'name'>), source_client: 'continue' as const })
              }
            }
          }
        } catch {
          // Skip individual files that fail to parse.
        }
      }
    } catch {
      // Directory read failed.
    }
  }

  return servers
}

/**
 * Parse a Continue.dev config.yaml file.
 * The mcpServers field is a YAML array of objects, not a keyed object.
 */
function parseContinueConfig(filePath: string): MCPServer[] {
  if (!fs.existsSync(filePath)) return []
  try {
    const raw = fs.readFileSync(filePath, 'utf8')

    // Dynamically import js-yaml to avoid hard dependency for users without Continue.
    let yaml: { load: (input: string) => unknown }
    try {
      yaml = require('js-yaml')
    } catch {
      // js-yaml not installed -- skip YAML parsing.
      return []
    }

    const config = yaml.load(raw) as { mcpServers?: ContinueServerDef[] } | null
    if (!config || !Array.isArray(config.mcpServers)) return []

    return config.mcpServers
      .filter((s) => s && typeof s.name === 'string')
      .map((s) => ({
        name: s.name,
        command: s.command,
        args: s.args,
        env: s.env,
        source_client: 'continue' as const,
      }))
  } catch {
    return []
  }
}
