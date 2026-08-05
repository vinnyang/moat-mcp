export const config = {
  databaseUrl:
    process.env.DATABASE_URL ??
    "postgres://mcp_readonly:moat_readonly_dev@127.0.0.1:5432/moat_mcp",
} as const;