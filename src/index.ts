#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import * as ynab from "ynab";

import { auditSinkFromEnv } from "./auditFile.js";
import { isReadOnly, registerAll } from "./registry.js";

const server = new McpServer({
  name: "ynab-mcp-server",
  version: "0.9.0",
});

// Initialize YNAB API
const api = new ynab.API(process.env.YNAB_API_TOKEN || "");

const readOnly = isReadOnly(process.env.YNAB_READ_ONLY);
let audit: ReturnType<typeof auditSinkFromEnv>;
try {
  audit = auditSinkFromEnv();
} catch (error) {
  console.error(`YNAB_AUDIT_LOG could not be opened (${error instanceof Error ? error.message : error}); refusing to start`);
  process.exit(1);
}
registerAll(server, api, { readOnly, audit });

// Start the server
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);

  console.error(`YNAB MCP server running on stdio${readOnly ? " (read-only)" : ""}${audit ? `, audit log ${audit.file}` : ""}`);
}

main().catch(console.error);
