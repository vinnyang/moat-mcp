import { config } from "./config.js";

if (config.transport === "http") {
  const { startHttpServer } = await import("./http.js");
  await startHttpServer();
} else {
  const { startStdioServer } = await import("./stdio.js");
  await startStdioServer();
}