import * as fs from 'fs'
import * as path from 'path'
import * as crypto from 'crypto'
import * as os from 'os'
import { discoverAllServers } from '../discovery/index.js'
import type { DriftEvent, DriftOptions, ToolBaseline, MCPServer } from '../types.js'

/**
 * Compute a SHA-256 hash of a string value.
 */
function sha256(value: string): string {
  return crypto.createHash('sha256').update(value).digest('hex')
}

/**
 * Load the baseline from a JSON file. Returns empty map if file does not exist.
 */
function loadBaseline(filePath: string): Map<string, ToolBaseline> {
  if (!fs.existsSync(filePath)) {
    return new Map()
  }
  try {
    const raw = fs.readFileSync(filePath, 'utf8')
    const entries: ToolBaseline[] = JSON.parse(raw)
    const map = new Map<string, ToolBaseline>()
    for (const entry of entries) {
      map.set(`${entry.server_name}:${entry.tool_name}`, entry)
    }
    return map
  } catch {
    return new Map()
  }
}

/**
 * Persist the baseline to a JSON file. Creates parent directories as needed.
 */
function saveBaseline(filePath: string, baseline: Map<string, ToolBaseline>): void {
  const dir = path.dirname(filePath)
  fs.mkdirSync(dir, { recursive: true })
  const entries = Array.from(baseline.values())
  fs.writeFileSync(filePath, JSON.stringify(entries, null, 2), 'utf8')
}

/**
 * Compare current tool state against stored baseline.
 * Returns a list of drift events for any changes detected.
 */
function detectDrift(servers: MCPServer[], baseline: Map<string, ToolBaseline>): DriftEvent[] {
  const events: DriftEvent[] = []
  const now = new Date().toISOString()
  const currentKeys = new Set<string>()

  for (const server of servers) {
    if (!server.tools) continue
    for (const tool of server.tools) {
      const key = `${server.name}:${tool.name}`
      currentKeys.add(key)
      const descHash = sha256(tool.description || '')
      const schemaHash = sha256(JSON.stringify(tool.inputSchema || {}))
      const existing = baseline.get(key)

      if (!existing) {
        // New tool: update baseline, emit added event.
        baseline.set(key, {
          server_name: server.name,
          tool_name: tool.name,
          description_hash: descHash,
          schema_hash: schemaHash,
          first_seen_at: now,
          last_seen_at: now,
        })
        events.push({
          server_name: server.name,
          tool_name: tool.name,
          event_type: 'added',
          new_hash: descHash,
          detected_at: now,
        })
      } else {
        let changed = false
        if (existing.description_hash !== descHash) {
          events.push({
            server_name: server.name,
            tool_name: tool.name,
            event_type: 'description_changed',
            old_hash: existing.description_hash,
            new_hash: descHash,
            detected_at: now,
          })
          changed = true
        }
        if (existing.schema_hash !== schemaHash) {
          events.push({
            server_name: server.name,
            tool_name: tool.name,
            event_type: 'schema_changed',
            old_hash: existing.schema_hash,
            new_hash: schemaHash,
            detected_at: now,
          })
          changed = true
        }
        if (changed) {
          baseline.set(key, {
            ...existing,
            description_hash: descHash,
            schema_hash: schemaHash,
            last_seen_at: now,
          })
        } else {
          baseline.set(key, { ...existing, last_seen_at: now })
        }
      }
    }
  }

  // Detect removed tools.
  for (const [key, entry] of baseline.entries()) {
    if (!currentKeys.has(key)) {
      events.push({
        server_name: entry.server_name,
        tool_name: entry.tool_name,
        event_type: 'removed',
        old_hash: entry.description_hash,
        detected_at: now,
      })
      baseline.delete(key)
    }
  }

  return events
}

/**
 * Post a drift event to the Shield API internal endpoint.
 */
async function postDriftEvent(event: DriftEvent, apiKey: string, apiBase: string): Promise<void> {
  try {
    await fetch(`${apiBase}/api/v1/internal/mcp-tool-trigger`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Shield-Internal-Secret': apiKey,
      },
      body: JSON.stringify({
        event_type: event.event_type,
        server_name: event.server_name,
        tool_name: event.tool_name,
        old_hash: event.old_hash,
        new_hash: event.new_hash,
        detected_at: event.detected_at,
      }),
    })
  } catch (err) {
    console.error(`drift: failed to post event: ${err instanceof Error ? err.message : String(err)}`)
  }
}

/**
 * Run the drift detector in watch mode.
 * On first run: establishes the baseline. On subsequent runs: detects and reports changes.
 */
export async function runWatchMode(opts: DriftOptions): Promise<void> {
  const baselineFile = opts.baselineFile || path.join(os.homedir(), '.config', 'sysmond', 'mcp_baselines.json')
  const apiBase = opts.apiBase || 'https://api.agentdefenders.ai'

  console.log(`drift: starting watch mode (interval: ${opts.intervalSeconds}s)`)
  if (!fs.existsSync(baselineFile)) {
    console.log(`drift: no baseline found at ${baselineFile} -- establishing baseline on first run`)
  }

  const runOnce = async (isFirstRun: boolean): Promise<void> => {
    const servers = discoverAllServers()
    const baseline = loadBaseline(baselineFile)
    const baselineWasEmpty = baseline.size === 0

    const events = detectDrift(servers, baseline)
    saveBaseline(baselineFile, baseline)

    if (baselineWasEmpty && isFirstRun) {
      console.log(`drift: baseline established with ${baseline.size} tool(s) across ${servers.length} server(s)`)
      return
    }

    const driftEvents = events.filter((e) => e.event_type !== 'added' || !baselineWasEmpty)
    if (driftEvents.length === 0) return

    for (const event of driftEvents) {
      console.log(`drift: ${event.event_type}  ${event.server_name}/${event.tool_name}  ${event.detected_at}`)
      if (opts.apiKey) {
        await postDriftEvent(event, opts.apiKey, apiBase)
      }
    }
  }

  let isFirstRun = true
  await runOnce(isFirstRun)
  isFirstRun = false

  setInterval(async () => {
    try {
      await runOnce(false)
    } catch (err) {
      console.error(`drift: scan error: ${err instanceof Error ? err.message : String(err)}`)
    }
  }, opts.intervalSeconds * 1000)

  // Keep process alive.
  await new Promise<never>(() => {})
}
