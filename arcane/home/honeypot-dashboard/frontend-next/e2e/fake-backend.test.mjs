// Unit-level check on the fixture itself (node:test, no browser/build
// needed): #2542 wants /api/v1/live to stop falling through the bare {}
// catch-all now that #2540 made the catch-all loud. Pins the stub shape
// directly against startFakeBackend rather than through a full matrix run.
import assert from "node:assert/strict";
import test from "node:test";

import { startFakeBackend } from "./fake-backend.mjs";

test("/api/v1/live answers a stub envelope, not the bare {} catch-all", async () => {
  const fake = await startFakeBackend();
  try {
    const res = await fetch(`${fake.url}/api/v1/live`);
    assert.equal(res.status, 200);
    const body = await res.json();
    // The bare catch-all is exactly {} with no keys -- assert the stub
    // carries the live-tail envelope shape instead.
    assert.deepEqual(Object.keys(body).sort(), ["cursor", "entries"]);
    assert.deepEqual(body.entries, []);
    assert.equal(body.cursor, null);
  } finally {
    fake.close();
  }
});

test("an unrecognized /api/v1/* path still falls through to the bare {} catch-all", async () => {
  const fake = await startFakeBackend();
  try {
    const res = await fetch(`${fake.url}/api/v1/not-a-real-route`);
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.deepEqual(body, {});
  } finally {
    fake.close();
  }
});
