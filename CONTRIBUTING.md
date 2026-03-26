# Contributing to @agentdefenders/mcp-scan

We welcome contributions, especially new MCP client discovery modules.

## How to add a new MCP client

Each client has its own discovery module in `src/discovery/`. The pattern is simple:

1. Create `src/discovery/{client}.ts` following the existing pattern (see `claude.ts` for reference)
2. Export a `discover{Client}Servers(configPath?: string): MCPServer[]` function
3. Handle all three platforms: macOS, Linux, Windows
4. Return `[]` on missing file, invalid JSON, or missing `mcpServers` key
5. Set `source_client` to your client identifier
6. Add the client ID to `ClientId` type in `src/discovery/index.ts`
7. Add the discoverer to the `discoverers` map in `src/discovery/index.ts`
8. Add the client to `CLIENT_DISPLAY_NAMES` in `src/reporters/console.ts`
9. Add the client to the `source_client` union in `src/types.ts`
10. Add tests in `tests/discovery.test.ts` (4 cases minimum: happy path, file not found, invalid JSON, missing key)
11. Update the client table in `README.md`

## Development

```bash
pnpm install
pnpm test          # run tests
pnpm run dev       # run CLI in dev mode
pnpm run build     # compile TypeScript
```

## Pull requests

- Keep PRs focused on a single change
- Include tests for new discovery modules
- Run `pnpm test` before submitting
- Note: the public repo is a mirror of a private monorepo. Force pushes happen on sync. Your PR branch may need rebasing after a sync. Keep PRs small to minimize rebase pain.

## Reporting issues

Use the issue templates for bug reports and feature requests. Include your OS, Node.js version, and which MCP clients you have installed.

## Code of conduct

Be respectful. We're building security tools for the community. Keep discussions constructive and focused on the technical merits.
