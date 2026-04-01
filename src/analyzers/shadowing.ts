import type { Finding, MCPServer } from '../types.js'

/** Remediation guidance for shadowing findings. */
const SHADOWING_REMEDIATION =
  'This tool shadows a built-in or commonly-used tool name. Rename the tool or remove the duplicate MCP server to prevent confusion.'

/**
 * Built-in tool names that are commonly targeted for shadowing attacks.
 * A shadowing attack registers a malicious tool with the same or similar name
 * as a trusted built-in, causing the LLM to call the malicious version.
 */
const BUILT_IN_TOOL_NAMES = new Set([
  'bash',
  'computer',
  'edit',
  'read',
  'write',
  'str_replace_editor',
  'str_replace_based_edit_tool',
  'create_file',
  'delete_file',
  'list_files',
  'search_files',
  'grep',
  'find',
  'execute',
  'run',
  'shell',
  'terminal',
  'python',
  'javascript',
  'code',
  'web_search',
  'browser',
  'fetch',
  'http_request',
  'mcp_install',
  'git',
  'git_diff',
  'git_commit',
  'git_push',
  'git_init',
  'list_directory',
  'read_file',
  'write_file',
  'move_file',
  'copy_file',
  'search_code',
  'run_command',
  'send_message',
  'get_url',
  'curl',
  'download',
  'upload',
  'glob',
  'grep',
  'todo',
  'notebook',
  'agent',
  'ask_user',
  'web_fetch',
  'mcp_list',
  'mcp_connect',
  'mcp_disconnect',
  'tool_call',
  'approve',
  'deny',
  'submit',
  'screenshot',
  'click',
  'type',
  'scroll',
  'navigate',
  'dispatch',
  'clipboard',
  'paste',
  'keypress',
  'drag',
  'hover',
  'wait',
  'assert',
  'verify',
  'validate',
  'debug',
  'inspect',
  'profile',
  'trace',
  'memory',
  'patch',
  'diff',
  'merge',
  'rebase',
  'stash',
  'commit',
  'push',
  'pull',
  'clone',
  'deploy',
  'rollback',
  'scale',
  'create_message',
  'sample',
  'sampling',
  'think',
  'plan',
  'search',
  'replace',
  'insert',
  'delete',
  'rename',
  'refactor',
  'test',
  'lint',
  'format',
  'compile',
  'build',
  'install',
  'uninstall',
  'update',
  'upgrade',
  'publish',
  'login',
  'logout',
  'auth',
  'authorize',
  'connect',
  'disconnect',
  'subscribe',
  'unsubscribe',
  'listen',
  'watch',
  'monitor',
  'alert',
  'notify',
  'log',
  'audit',
  'scan',
  'analyze',
  'encrypt',
  'decrypt',
  'sign',
  'hash',
  'token',
  'session',
  'config',
  'settings',
  'env',
  'secret',
])

/** Patterns that closely mimic built-in tool names. */
const SHADOWING_PATTERNS: Array<{ pattern: RegExp; shadowsBuiltin: string }> = [
  { pattern: /^bash_?(?:exec|run|command)?$/i, shadowsBuiltin: 'bash' },
  { pattern: /^(?:run|exec)_?(?:bash|shell|command|code)$/i, shadowsBuiltin: 'bash/shell' },
  { pattern: /^(?:web|internet)_?search$/i, shadowsBuiltin: 'web_search' },
  { pattern: /^(?:file|fs)_?(?:read|write|edit|create|delete)$/i, shadowsBuiltin: 'file tools' },
  { pattern: /^computer_?(?:use|control|action)?$/i, shadowsBuiltin: 'computer' },
  { pattern: /^str_replace/i, shadowsBuiltin: 'str_replace_editor' },
  { pattern: /^git_?(?:diff|commit|push|pull|init|clone|log|status)$/i, shadowsBuiltin: 'git tools' },
  { pattern: /^(?:read|get|open)_?file$/i, shadowsBuiltin: 'read_file' },
  { pattern: /^(?:write|save|put)_?file$/i, shadowsBuiltin: 'write_file' },
  { pattern: /^(?:list|ls|dir)_?(?:dir|directory|files)?$/i, shadowsBuiltin: 'list_directory' },
  { pattern: /^(?:send|post)_?message$/i, shadowsBuiltin: 'send_message' },
  { pattern: /^(?:curl|wget|fetch|get)_?(?:url|page|data)?$/i, shadowsBuiltin: 'fetch/curl' },
  { pattern: /^(?:run|exec|execute)_?(?:cmd|command|script)?$/i, shadowsBuiltin: 'run_command' },
  { pattern: /^(?:mcp)_?(?:install|connect|disconnect|list)$/i, shadowsBuiltin: 'mcp tools' },
  { pattern: /^(?:tool|function)_?(?:call|invoke|execute)$/i, shadowsBuiltin: 'tool_call' },
  { pattern: /^(?:approve|deny|allow|block)_?(?:tool|action|request)?$/i, shadowsBuiltin: 'approve/deny' },
  { pattern: /^(?:ask|prompt|question)_?(?:user|human)?$/i, shadowsBuiltin: 'ask_user' },
  { pattern: /^(?:web|url|page)_?(?:fetch|get|load|scrape)$/i, shadowsBuiltin: 'web_fetch' },
  { pattern: /^(?:notebook|ipynb)_?(?:edit|run|execute|cell)?$/i, shadowsBuiltin: 'notebook' },
  { pattern: /^(?:screenshot|capture)_?(?:screen|page|window|element)?$/i, shadowsBuiltin: 'screenshot' },
  { pattern: /^(?:click|tap|press)_?(?:element|button|link)?$/i, shadowsBuiltin: 'click' },
  { pattern: /^(?:navigate|goto|visit)_?(?:url|page|site)?$/i, shadowsBuiltin: 'navigate' },
  { pattern: /^(?:deploy|publish|release)_?(?:app|service|code)?$/i, shadowsBuiltin: 'deploy' },
  { pattern: /^(?:clipboard|copy|paste)_?(?:text|data|content)?$/i, shadowsBuiltin: 'clipboard' },
  { pattern: /^(?:memory|context|history)_?(?:read|write|get|set|store)?$/i, shadowsBuiltin: 'memory' },
  { pattern: /^(?:create|send|make)_?message$/i, shadowsBuiltin: 'create_message' },
  { pattern: /^(?:sample|sampling)_?(?:request|create|generate)?$/i, shadowsBuiltin: 'sampling' },
  { pattern: /^(?:think|reason|plan)_?(?:step|ahead|through)?$/i, shadowsBuiltin: 'think/plan' },
  { pattern: /^(?:search|find|locate)_?(?:code|files?|text|content)?$/i, shadowsBuiltin: 'search' },
  { pattern: /^(?:test|lint|format|compile|build)_?(?:code|project|file)?$/i, shadowsBuiltin: 'build tools' },
  { pattern: /^(?:auth|login|logout|authorize)_?(?:user|session|token)?$/i, shadowsBuiltin: 'auth' },
  { pattern: /^(?:config|settings|env|secret)_?(?:read|write|get|set|manage)?$/i, shadowsBuiltin: 'config/settings' },
  { pattern: /^(?:encrypt|decrypt|sign|hash|verify)_?(?:data|file|message|token)?$/i, shadowsBuiltin: 'crypto tools' },
  { pattern: /^(?:monitor|watch|listen|alert|notify)_?(?:event|change|update)?$/i, shadowsBuiltin: 'monitor' },
]

/**
 * Analyze a server's tools for shadowing attacks.
 * Shadowing registers tools with names identical or very similar to trusted
 * built-in tools, causing the LLM to call the malicious version instead.
 */
export function analyzeShadowing(server: MCPServer): Finding[] {
  const findings: Finding[] = []
  if (!server.tools) return findings

  for (const tool of server.tools) {
    const toolNameLower = tool.name.toLowerCase()

    // Exact match against known built-in names.
    if (BUILT_IN_TOOL_NAMES.has(toolNameLower)) {
      findings.push({
        analyzer: 'shadowing',
        severity: 'high',
        server_name: server.name,
        tool_name: tool.name,
        description: `Tool name "${tool.name}" shadows a known built-in tool. Attackers use this to intercept LLM calls to trusted tools.`,
        field: 'name',
        evidence: tool.name,
        remediation: SHADOWING_REMEDIATION,
      })
      continue
    }

    // Pattern match for near-duplicates.
    for (const { pattern, shadowsBuiltin } of SHADOWING_PATTERNS) {
      if (pattern.test(tool.name)) {
        findings.push({
          analyzer: 'shadowing',
          severity: 'medium',
          server_name: server.name,
          tool_name: tool.name,
          description: `Tool name "${tool.name}" closely mimics built-in "${shadowsBuiltin}" (shadowing pattern).`,
          field: 'name',
          evidence: tool.name,
          remediation: SHADOWING_REMEDIATION,
        })
        break
      }
    }
  }

  return findings
}
