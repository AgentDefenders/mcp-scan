import * as fs from 'fs'
import * as path from 'path'
import * as crypto from 'crypto'
import * as os from 'os'
import { discoverAllServers } from '../discovery/index.js'
import { computeGrade } from '../analyzers/index.js'
import type { DriftEvent, DriftOptions, ToolBaseline, MCPServer, Severity, Grade, Finding } from '../types.js'

/** A finding produced from a drift event, shaped for the scan results API. */
interface DriftFinding {
  server_name: string
  tool_name: string
  event_type: DriftEvent['event_type']
  severity: Severity
  old_hash?: string
  new_hash?: string
  detected_at: string
}

/** Payload sent to POST /api/v1/scans for a drift detection result. */
interface DriftScanPayload {
  scan_type: 'mcp_drift'
  overall_grade: Grade
  finding_count: number
  findings: string    // JSON-stringified DriftFinding[]
  scanner_version: string
  raw_result: string  // JSON-stringified original DriftEvent[]
}

const DRIFT_SEVERITY: Record<DriftEvent['event_type'], Severity> = {
  description_changed: 'high',
  removed: 'high',
  schema_changed: 'medium',
  added: 'low',
}

/**
 * Convert a list of drift events into a scan result payload for POST /api/v1/scans.
 * Exported for testing.
 */
export function buildDriftScanPayload(events: DriftEvent[]): DriftScanPayload {
  const findings: DriftFinding[] = events.map((e) => ({
    server_name: e.server_name,
    tool_name: e.tool_name,
    event_type: e.event_type,
    severity: DRIFT_SEVERITY[e.event_type] ?? 'medium',
    old_hash: e.old_hash,
    new_hash: e.new_hash,
    detected_at: e.detected_at,
  }))

  // computeGrade only reads .severity, so casting DriftFinding[] to Finding[]
  // is safe — the rest of the Finding fields are never accessed.
  const grade = computeGrade(findings as unknown as Finding[])

  return {
    scan_type: 'mcp_drift',
    overall_grade: grade,
    finding_count: findings.length,
    findings: JSON.stringify(findings),
    scanner_version: '0.1.0',
    raw_result: JSON.stringify(events),
  }
}

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
 * Upload a batch of drift events as a single mcp_drift scan result to POST /api/v1/scans.
 * Uses Authorization: Bearer (dashboard auth group) instead of X-Shield-Internal-Secret.
 * Drift events are scan results, not canary triggers — they don't have a canary_token_id.
 */
async function postDriftScan(events: DriftEvent[], apiKey: string, apiBase: string): Promise<void> {
  if (events.length === 0) return
  const payload = buildDriftScanPayload(events)
  try {
    const res = await fetch(`${apiBase}/api/v1/scans`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${apiKey}`,
      },
      body: JSON.stringify(payload),
    })
    if (!res.ok) {
      console.error(`drift: failed to upload scan result: HTTP ${res.status}`)
    }
  } catch (err) {
    console.error(`drift: failed to upload scan result: ${err instanceof Error ? err.message : String(err)}`)
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
    }
    if (opts.apiKey && driftEvents.length > 0) {
      await postDriftScan(driftEvents, opts.apiKey, apiBase)
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
