# @agentdefenders/mcp-scan

Security scanner for Model Context Protocol (MCP) server configurations. Detects tool poisoning, prompt injection, shadowing attacks, and known threats.

[![npm version](https://img.shields.io/npm/v/@agentdefenders/mcp-scan)](https://www.npmjs.com/package/@agentdefenders/mcp-scan)
[![license](https://img.shields.io/npm/l/@agentdefenders/mcp-scan)](./LICENSE)
[![node](https://img.shields.io/node/v/@agentdefenders/mcp-scan)](https://nodejs.org)

MCP servers extend AI agents with powerful tool-use capabilities, but they also introduce a new attack surface. A compromised or malicious MCP server can exfiltrate data, override agent behavior, or act as a supply chain backdoor. `@agentdefenders/mcp-scan` analyzes your MCP configurations and flags security issues before they reach production.

All analysis runs locally on your machine. No data is transmitted to any external service. If you want dashboard integration and historical tracking, you can optionally provide `--api-key` to sync results with [AgentDefenders Shield](https://app.agentdefenders.ai).

## Quick Start

```
npx @agentdefenders/mcp-scan
```

The scanner auto-detects MCP client configurations (Claude Desktop, Cursor, VS Code, Windsurf, Gemini CLI) and analyzes all registered servers.

## Example Output

```
@agentdefenders/mcp-scan v0.2.0

Scanning MCP configurations...
Found 2 servers across 1 client configuration.

--- filesystem-server ---
  Source: claude_desktop_config.json
  Command: npx -y @modelcontextprotocol/server-filesystem /home/user/projects
  Tools: 11 detected
  Analyzers: 5/5 passed
  Grade: A

--- data-pipeline-mcp ---
  Source: claude_desktop_config.json
  Command: npx -y data-pipeline-mcp@latest
  Tools: 4 detected
  Findings:
    [HIGH] tool-poisoning: Tool "run_query" description contains hidden
           instruction that overrides agent behavior. The phrase "ignore
           previous instructions" was detected in the tool description.
    [LOW]  suspicious-env: Tool "connect" requests access to DATABASE_URL
           environment variable.
  Grade: D

Summary
  Servers scanned: 2
  Total findings:  2 (1 high, 0 medium, 1 low)
  Clean servers:   1
  Flagged servers: 1
```

## Supported MCP Clients

| Client | macOS | Linux | Windows |
|---|---|---|---|
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` | `~/.config/Claude/claude_desktop_config.json` | `%APPDATA%\Claude\claude_desktop_config.json` |
| Cursor | `~/Library/Application Support/Cursor/User/globalStorage/cursor.mcp/config.json` | `~/.config/Cursor/User/globalStorage/cursor.mcp/config.json` | `%APPDATA%\Cursor\User\globalStorage\cursor.mcp\config.json` |
| VS Code 1.99+ | `~/Library/Application Support/Code/User/globalStorage/vscode.mcp/config.json` | `~/.config/Code/User/globalStorage/vscode.mcp/config.json` | `%APPDATA%\Code\User\globalStorage\vscode.mcp\config.json` |
| Windsurf | `~/Library/Application Support/Windsurf/User/globalStorage/windsurf.mcp/config.json` | `~/.config/Windsurf/User/globalStorage/windsurf.mcp/config.json` | `%APPDATA%\Windsurf\User\globalStorage\windsurf.mcp\config.json` |
| Google Gemini CLI | `~/.gemini/settings.json` | `~/.gemini/settings.json` | `%USERPROFILE%\.gemini\settings.json` |

You can also point to a specific config file with `--config <path>`.

## Security Analyzers

| Analyzer | Description |
|---|---|
| `tool-poisoning` | Detects hidden instructions in tool descriptions that attempt to override agent behavior or exfiltrate data. |
| `prompt-injection` | Identifies prompt injection patterns in server metadata, tool names, and parameter schemas. |
| `shadowing` | Flags tools that shadow or redefine built-in tool names, potentially hijacking agent actions. |
| `suspicious-env` | Reports tools that request access to sensitive environment variables (credentials, tokens, keys). |
| `known-threats` | Checks server packages against a curated database of known-malicious MCP servers. |

## Output Formats

The default output is a human-readable console report. For automation, use structured formats:

```bash
# JSON output
npx @agentdefenders/mcp-scan --format json

# SARIF output (for GitHub Code Scanning and other SARIF consumers)
npx @agentdefenders/mcp-scan --format sarif
```

## CI/CD Integration

Add MCP configuration scanning to your CI pipeline. The `--fail-on` flag sets the exit code to 1 if any finding meets or exceeds the specified severity.

### GitHub Actions

```yaml
- name: Scan MCP configurations
  run: npx @agentdefenders/mcp-scan --format sarif --fail-on high > mcp-scan.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: mcp-scan.sarif
```

## CLI Reference

| Flag | Description | Default |
|---|---|---|
| `--config <path>` | Path to a specific MCP client configuration file. | Auto-detect |
| `--format <type>` | Output format: `console`, `json`, `sarif`. | `console` |
| `--fail-on <severity>` | Exit with code 1 if any finding meets or exceeds severity: `low`, `medium`, `high`, `critical`. | Disabled |
| `--api-key <key>` | AgentDefenders API key for dashboard sync. Enables remote result storage. | None |
| `--watch` | Continuously monitor configuration files for changes and re-scan on modification. | Disabled |
| `--interval <seconds>` | Polling interval in seconds when using `--watch`. | `30` |
| `--quiet` | Suppress all output except findings and errors. | Disabled |
| `--badge` | Generate a shield badge URL for your project README. | Disabled |

## Privacy

All analysis runs locally on your machine. No data is sent to any external service unless you explicitly provide `--api-key` for dashboard integration.

## Links

- [Documentation](https://docs.agentdefenders.ai/mcp-scan)
- [Dashboard Sign Up](https://app.agentdefenders.ai)
- [Report a Vulnerability](https://github.com/AgentDefenders/mcp-scan/security/advisories)

## License

[MIT](./LICENSE)
