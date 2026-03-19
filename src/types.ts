/** Severity level of a security finding. */
export type Severity = 'critical' | 'high' | 'medium' | 'low'

/** Security grade derived from findings. */
export type Grade = 'A' | 'B' | 'C' | 'D' | 'F'

/** Analyzer that produced a finding. */
export type AnalyzerName = 'tool-poisoning' | 'prompt-injection' | 'shadowing'

/** A single security finding from the scanner. */
export interface Finding {
  /** Analyzer that detected this issue. */
  analyzer: AnalyzerName
  /** Severity of this finding. */
  severity: Severity
  /** MCP server name where the finding was detected. */
  server_name: string
  /** Tool name within the server. */
  tool_name: string
  /** Human-readable description of the issue. */
  description: string
  /** The specific field that triggered the finding (e.g. "description"). */
  field: string
  /** The matched pattern or snippet that triggered the finding. */
  evidence: string
}

/** Per-server scan summary. */
export interface ServerScanResult {
  server_name: string
  grade: Grade
  tool_count: number
  findings: Finding[]
}

/** Complete result of a single mcp-scan run. */
export interface ScanResult {
  /** Timestamp when the scan started. */
  scanned_at: string
  /** Overall grade across all servers. */
  overall_grade: Grade
  /** Total number of findings across all servers. */
  finding_count: number
  /** Per-server results. */
  servers: ServerScanResult[]
  /** All findings flattened. */
  findings: Finding[]
  /** Scanner version. */
  scanner_version: string
}

/** A discovered MCP server configuration. */
export interface MCPServer {
  /** The key used in the config file (e.g. "my-server"). */
  name: string
  /** Command to launch the server. */
  command?: string
  args?: string[]
  env?: Record<string, string>
  /** Tools reported by the server (populated if --enumerate flag is used). */
  tools?: MCPTool[]
}

/** A discovered MCP tool definition. */
export interface MCPTool {
  name: string
  description: string
  inputSchema?: Record<string, unknown>
}

/** Raw MCP configuration file structure. */
export interface MCPConfig {
  mcpServers?: Record<string, Omit<MCPServer, 'name'>>
}

/** Options for the drift detector. */
export interface DriftOptions {
  intervalSeconds: number
  apiKey?: string
  apiBase?: string
  baselineFile?: string
}

/** A baseline entry for drift detection. */
export interface ToolBaseline {
  server_name: string
  tool_name: string
  description_hash: string
  schema_hash: string
  first_seen_at: string
  last_seen_at: string
}

/** A drift event detected during --watch mode. */
export interface DriftEvent {
  server_name: string
  tool_name: string
  event_type: 'added' | 'removed' | 'description_changed' | 'schema_changed'
  old_hash?: string
  new_hash?: string
  detected_at: string
}
