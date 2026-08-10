import { createServer } from "node:http";

// A minimal in-memory stand-in for Elasticsearch's document CRUD API --
// GET/PUT/DELETE on _doc (including op_type=create and if_seq_no/
// if_primary_term optimistic concurrency) and a plain _search -- just enough
// of the real contract for dashboard/elastic.go's docGet/docIndex/docDelete/
// docSearchAll to round-trip against. This is the Node mirror of
// dashboard/alerts_test.go's memESDocStore, used so the browser e2e suite
// can exercise ES-only features (Payload Workbench, alerts, reports,
// payload inventory, static-analysis cache) without a real Elasticsearch
// cluster in CI.
export function startFakeElasticsearch() {
  const docs = new Map(); // "index/id" -> { seqNo, primaryTerm, source }
  // sensor -> raw honeypot event body (the shape classify() consumes,
  // unwrapped -- this fixture wraps it under _source.honeypot itself on the
  // way out, matching honeypot-v2-*'s real document shape). #1103: cowrie/
  // dionaea/conpot/... read Elasticsearch exclusively now, no local-file
  // fallback, so the e2e fixture has to seed their events here instead of
  // (or as well as) the local log files start-dashboard.mjs still writes
  // for the sensors that keep a local read path (suricata, portbridge).
  const sensorEvents = new Map();
  const pits = new Set();

  const server = createServer((req, res) => {
    const url = new URL(req.url, "http://fake-es");
    const parts = url.pathname.replace(/^\//, "").split("/");

    // #1103: loadSensorEventsES opens a point-in-time scoped to
    // honeypot-v2-* (POST /<pattern>/_pit) and then searches via a bodyless-
    // of-index POST /_search that carries the PIT id in its body instead --
    // answer both before the dashboard-* index gate below, which would
    // otherwise 503 the bare /_search (no index segment at all).
    if (parts.length === 2 && parts[1] === "_pit" && req.method === "POST") {
      const id = `fake-pit-${pits.size}`;
      pits.add(id);
      res.setHeader("Content-Type", "application/json");
      res.writeHead(200);
      res.end(JSON.stringify({ id }));
      return;
    }
    if (parts.length === 1 && parts[0] === "_pit" && req.method === "DELETE") {
      readBody(req).then(() => {
        res.setHeader("Content-Type", "application/json");
        res.writeHead(200);
        res.end(JSON.stringify({ succeeded: true }));
      });
      return;
    }
    if (parts.length === 1 && parts[0] === "_search" && req.method === "POST") {
      readBody(req).then((body) => {
        const req_ = body.length ? JSON.parse(body) : {};
        const filters = req_.query?.bool?.filter ?? [];
        const sensorFilter = filters.find((f) => f.term?.["event.sensor"] !== undefined);
        res.setHeader("Content-Type", "application/json");
        res.writeHead(200);
        if (!sensorFilter) {
          // The #39 overview aggregation query, not a per-sensor search --
          // this fixture doesn't back it with real aggregation buckets
          // (fetchESOverview's own ok=false path is already exercised and
          // tolerated by every caller, same as before #1103).
          res.end(JSON.stringify({ hits: { hits: [] } }));
          return;
        }
        const events = sensorEvents.get(sensorFilter.term["event.sensor"]) ?? [];
        const hits = events.map((source) => ({ _source: { honeypot: source } }));
        res.end(JSON.stringify({ hits: { hits } }));
      });
      return;
    }

    // Only the dashboard's own bookkeeping indices (dashboard-*) are backed
    // by real in-memory state here. Everything else -- suricata-*,
    // portbridge-v2-*, dead-letter-honeypot*, _cluster/health, _count -- is
    // sensor telemetry this fixture never ingests. Answering those with a
    // confident "200, zero hits" would make the dashboard trust an empty
    // Elasticsearch over the real fixture data it should read instead (a
    // local-file read for suricata/portbridge, which still have one; a
    // seeded sensorEvents entry for everything else, which the two branches
    // above already answer for real). A non-2xx response here is exactly
    // what a real cluster that hasn't ingested this data would never
    // produce, but it reaches the same "ES has nothing for this" handling
    // every caller already has.
    if (parts[0] !== undefined && !parts[0].startsWith("dashboard-")) {
      res.writeHead(503);
      res.end(JSON.stringify({ error: "index not stubbed in fake-elasticsearch" }));
      return;
    }

    if (parts.length === 3 && parts[1] === "_doc") {
      const index = parts[0];
      const id = decodeURIComponent(parts[2]);
      const key = `${index}/${id}`;
      if (req.method === "GET") {
        const doc = docs.get(key);
        res.setHeader("Content-Type", "application/json");
        if (!doc) {
          res.writeHead(404);
          res.end(JSON.stringify({ found: false }));
          return;
        }
        res.writeHead(200);
        res.end(JSON.stringify({ _id: id, _seq_no: doc.seqNo, _primary_term: doc.primaryTerm, _source: doc.source, found: true }));
        return;
      }
      if (req.method === "PUT") {
        readBody(req).then((body) => {
          const source = body.length ? JSON.parse(body) : {};
          res.setHeader("Content-Type", "application/json");
          if (url.searchParams.get("op_type") === "create") {
            if (docs.has(key)) {
              res.writeHead(409);
              res.end(JSON.stringify({ error: { type: "version_conflict_engine_exception" } }));
              return;
            }
            docs.set(key, { seqNo: 0, primaryTerm: 1, source });
            res.writeHead(201);
            res.end(JSON.stringify({ result: "created" }));
            return;
          }
          const wantSeq = url.searchParams.get("if_seq_no");
          const wantTerm = url.searchParams.get("if_primary_term");
          const existing = docs.get(key);
          if (!existing || String(existing.seqNo) !== wantSeq || String(existing.primaryTerm) !== wantTerm) {
            res.writeHead(409);
            res.end(JSON.stringify({ error: { type: "version_conflict_engine_exception" } }));
            return;
          }
          docs.set(key, { seqNo: existing.seqNo + 1, primaryTerm: existing.primaryTerm, source });
          res.writeHead(200);
          res.end(JSON.stringify({ result: "updated" }));
        });
        return;
      }
      if (req.method === "DELETE") {
        res.setHeader("Content-Type", "application/json");
        if (!docs.has(key)) {
          res.writeHead(404);
          res.end(JSON.stringify({ result: "not_found" }));
          return;
        }
        docs.delete(key);
        res.writeHead(200);
        res.end(JSON.stringify({ result: "deleted" }));
        return;
      }
      res.writeHead(405);
      res.end();
      return;
    }

    if (parts.length === 2 && parts[1] === "_search") {
      const index = parts[0];
      const prefix = `${index}/`;
      const hits = [];
      for (const [key, doc] of docs) {
        if (!key.startsWith(prefix)) continue;
        hits.push({ _id: key.slice(prefix.length), _seq_no: doc.seqNo, _primary_term: doc.primaryTerm, _source: doc.source });
      }
      res.setHeader("Content-Type", "application/json");
      res.writeHead(200);
      res.end(JSON.stringify({ hits: { hits } }));
      return;
    }

    // Everything else (cluster health, _count, filebeat, sensor telemetry
    // searches) is background polling this fixture does not need to answer
    // -- esClient's own callers already treat a non-2xx/parse failure here
    // as "stat unavailable," not a hard error.
    res.writeHead(404);
    res.end(JSON.stringify({ error: "not stubbed in fake-elasticsearch" }));
  });

  return new Promise((resolvePromise) => {
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      resolvePromise({
        url: `http://127.0.0.1:${port}`,
        close: () => server.close(),
        // seedSensorEvents(sensor, events): register raw honeypot event
        // bodies (unwrapped, classify()'s own input shape) so a
        // loadSensorEventsES query for `sensor` returns them. Additive --
        // safe to call more than once for the same sensor.
        seedSensorEvents: (sensor, events) => {
          sensorEvents.set(sensor, [...(sensorEvents.get(sensor) ?? []), ...events]);
        },
      });
    });
  });
}

function readBody(req) {
  return new Promise((resolvePromise, reject) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => resolvePromise(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}
