import { spawn } from "node:child_process";
import { createServer } from "node:net";

// The dashboard's session store (lib/session.server.ts) needs a real Redis
// to talk to, and the fixture sessions the matrix seeds must survive across
// workers. Reimplementing RESP would be more fixture code than spawning the
// real binary on a throwaway port with persistence disabled -- carried over
// unchanged in spirit from the Go tier's suite (#1034), which made the same
// trade for the same reason.
export async function startFakeRedis() {
  const port = await getFreePort();
  const child = spawn("redis-server", [
    "--port", String(port),
    "--bind", "127.0.0.1",
    "--save", "",
    "--appendonly", "no",
    "--daemonize", "no",
  ], { stdio: ["ignore", "pipe", "inherit"] });

  await new Promise((resolvePromise, reject) => {
    let out = "";
    const onData = (chunk) => {
      out += chunk.toString();
      if (out.includes("Ready to accept connections")) {
        child.stdout.off("data", onData);
        resolvePromise();
      }
    };
    child.stdout.on("data", onData);
    child.once("error", reject);
    child.once("exit", (code, signal) => {
      if (code !== 0 && code !== null) {
        reject(new Error(`redis-server exited early with code ${code} (signal ${signal})`));
      }
    });
  });

  return {
    url: `redis://127.0.0.1:${port}/0`,
    port,
    close: () => child.kill(),
  };
}

function getFreePort() {
  return new Promise((resolvePromise, reject) => {
    const srv = createServer();
    srv.listen(0, "127.0.0.1", () => {
      const { port } = srv.address();
      srv.close(() => resolvePromise(port));
    });
    srv.on("error", reject);
  });
}
