import pg from "pg";
import { config } from "../config.js";

const { Pool } = pg;

export const pool = new Pool({
  connectionString: config.databaseUrl,
  max: 10,
  connectionTimeoutMillis: 5000,
  // Server-side caps: a query that outruns these is killed by Postgres itself,
  // so a slow or abandoned statement cannot hold a pooled connection open.
  statement_timeout: config.statementTimeoutMs,
  idle_in_transaction_session_timeout: config.idleInTransactionTimeoutMs,
});