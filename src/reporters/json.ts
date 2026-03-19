import type { ScanResult } from '../types.js'

/**
 * Format a scan result as machine-readable JSON.
 * Used by --format json flag and programmatic consumers.
 */
export function formatJSON(result: ScanResult): string {
  return JSON.stringify(result, null, 2)
}

/**
 * Print scan result as JSON to stdout.
 */
export function printJSONReport(result: ScanResult): void {
  console.log(formatJSON(result))
}
