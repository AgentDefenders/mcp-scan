import { describe, it, expect } from 'vitest'
import type { DriftEvent } from '../src/types.js'
import { buildDriftScanPayload } from '../src/drift/index.js'

describe('buildDriftScanPayload', () => {
  it('maps description_changed to high severity finding', () => {
    const events: DriftEvent[] = [
      {
        server_name: 'my-server',
        tool_name: 'admin_tool',
        event_type: 'description_changed',
        old_hash: 'abc123',
        new_hash: 'def456',
        detected_at: '2026-03-19T00:00:00Z',
      },
    ]
    const payload = buildDriftScanPayload(events)
    expect(payload.scan_type).toBe('mcp_drift')
    expect(payload.finding_count).toBe(1)
    expect(payload.overall_grade).toBe('D')
    const findings = JSON.parse(payload.findings)
    expect(findings[0].severity).toBe('high')
    expect(findings[0].server_name).toBe('my-server')
    expect(findings[0].tool_name).toBe('admin_tool')
    expect(findings[0].event_type).toBe('description_changed')
  })

  it('maps schema_changed to medium severity', () => {
    const events: DriftEvent[] = [
      {
        server_name: 's',
        tool_name: 't',
        event_type: 'schema_changed',
        old_hash: 'a',
        new_hash: 'b',
        detected_at: '2026-03-19T00:00:00Z',
      },
    ]
    const payload = buildDriftScanPayload(events)
    const findings = JSON.parse(payload.findings)
    expect(findings[0].severity).toBe('medium')
    expect(payload.overall_grade).toBe('C')
  })

  it('maps removed to high severity', () => {
    const events: DriftEvent[] = [
      {
        server_name: 's',
        tool_name: 't',
        event_type: 'removed',
        old_hash: 'a',
        detected_at: '2026-03-19T00:00:00Z',
      },
    ]
    const payload = buildDriftScanPayload(events)
    const findings = JSON.parse(payload.findings)
    expect(findings[0].severity).toBe('high')
  })

  it('maps added to low severity', () => {
    const events: DriftEvent[] = [
      {
        server_name: 's',
        tool_name: 't',
        event_type: 'added',
        new_hash: 'a',
        detected_at: '2026-03-19T00:00:00Z',
      },
    ]
    const payload = buildDriftScanPayload(events)
    const findings = JSON.parse(payload.findings)
    expect(findings[0].severity).toBe('low')
    expect(payload.overall_grade).toBe('B')
  })

  it('returns grade A for empty events', () => {
    const payload = buildDriftScanPayload([])
    expect(payload.overall_grade).toBe('A')
    expect(payload.finding_count).toBe(0)
  })

  it('high grade wins when mixed high and medium findings present', () => {
    const events: DriftEvent[] = [
      { server_name: 's', tool_name: 't1', event_type: 'description_changed', old_hash: 'a', new_hash: 'b', detected_at: '2026-03-19T00:00:00Z' },
      { server_name: 's', tool_name: 't2', event_type: 'schema_changed', old_hash: 'a', new_hash: 'b', detected_at: '2026-03-19T00:00:00Z' },
    ]
    const payload = buildDriftScanPayload(events)
    expect(payload.finding_count).toBe(2)
    expect(payload.overall_grade).toBe('D')
  })
})
