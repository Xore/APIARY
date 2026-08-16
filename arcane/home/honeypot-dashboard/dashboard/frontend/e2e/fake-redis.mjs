import { spawn } from "node:child_process";
import { createServer } from "node:net";

// #1034: dashboard/oidc_auth.go's newOIDCAuth() requires OIDC_SESSION_REDIS_URL
// and Pings it at startup, so the e2e dashboard needs a real Redis to talk
// to. Reimplementing RESP would be a lot more fixture code than just
// spawning the real binary on a throwaway port with persistence disabled --
// this is the Node mirror of fake-elasticsearch.mjs's approach, but for a
// protocol that already has a trivial single-binary implementation
// available instead of one worth hand-rolling.
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
