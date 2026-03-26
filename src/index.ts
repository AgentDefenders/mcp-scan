/**
 * Programmatic API for @agentdefenders/mcp-scan.
 * Import this to integrate the scanner into your own tools or CI pipelines.
 */

export type { Finding, ScanResult, ServerScanResult, ScanSummary, Grade, Severity, MCPServer, MCPTool, MCPConfig, DriftEvent, ToolBaseline } from './types.js'
export { discoverAllServers } from './discovery/index.js'
export { analyzeAll, analyzeServer, computeGrade } from './analyzers/index.js'
export { analyzeToolPoisoning } from './analyzers/tool-poisoning.js'
export { analyzePromptInjection } from './analyzers/prompt-injection.js'
export { analyzeShadowing } from './analyzers/shadowing.js'
export { analyzeKnownThreats, getKnownThreatCount } from './analyzers/known-threats.js'
export { formatJSON } from './reporters/json.js'
