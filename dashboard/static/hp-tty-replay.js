// #612/#638/#1282: in-browser playback of a cowrie TTY session recording,
// rendered by the real xterm.js terminal emulator (vendored, static/
// xterm.js -- see that file's own header) rather than this file's former
// hand-rolled VT100 subset (cursor movement, erase-line/erase-display, SGR
// colour codes only). That subset was a deliberate call at the time
// (#612/#638), not an oversight: "good enough to read a typical cowrie
// session... not a full terminal emulator." #1282 revisited that tradeoff
// -- full ANSI/VT fidelity (alternate screen buffer, more complete escape
// handling, real scrollback) was worth the added vendored-dependency
// weight. Clean replacement, not a dual-implementation fallback, per this
// codebase's own #1244 convention ("research replacing hand-written
// JavaScript with vendored libraries" favors a clean swap over maintaining
// two renderers of the same thing) -- anything genuinely exotic still
// round-trips correctly through the ".cast" download either way.
(function () {
  "use strict";

  var COLS = 80, ROWS = 24;

  // openTerminalUnderCSP (#1282): xterm.js's DOM renderer applies SGR
  // colours/bold via CSS classes (xterm-fg-N, xterm-bold, ...), resolved
  // by a <style> block it creates and appends to the DOM itself, with no
  // nonce -- confirmed directly against this vendored build (5.5.0) and
  // the current @xterm/xterm latest (6.0.0): neither's public API exposes
  // any nonce/CSP option. render.go's CSP has no bare 'unsafe-inline' on
  // style-src (nonce-gated, by design -- see render.go's own comment on
  // why style-src-attr was added instead of weakening style-src itself for
  // ECharts' similar-but-different inline-style-ATTRIBUTE need), so this
  // nonce-less <style> BLOCK is silently dropped by the browser: the
  // element and its rules exist in the DOM (confirmed live, textContent
  // intact) but never take visual effect, and Chrome logs nothing to the
  // console for it either. Confirmed live that setting `.nonce` on the
  // element AFTER xterm.js has already inserted it does nothing -- the
  // browser locks in the missing-nonce verdict at insertion time. The only
  // technique that works, confirmed live: intercept document.createElement
  // for the exact call that creates each <style> tag and stamp the page's
  // own nonce onto it BEFORE xterm.js appends it, borrowing the nonce off
  // an inline <script nonce="..."> the shared "style" template partial
  // already emits on every page (a script's own consumed nonce is still
  // readable via its .nonce IDL property from same-page JS, unlike the
  // nonce="" HTML attribute browsers deliberately blank out).
  function openTerminalUnderCSP(term, container) {
    var nonceSource = document.querySelector("script[nonce]");
    var nonce = nonceSource ? nonceSource.nonce : "";
    if (!nonce) { term.open(container); return; }
    var originalCreateElement = document.createElement.bind(document);
    document.createElement = function (tagName) {
      var el = originalCreateElement(tagName);
      if (String(tagName).toLowerCase() === "style") el.nonce = nonce;
      return el;
    };
    try {
      term.open(container);
    } finally {
      document.createElement = originalCreateElement;
    }
  }

  function init() {
    var root = document.getElementById("tty-viewer");
    if (!root) return;
    if (typeof Terminal === "undefined") {
      var screenElFallback = document.getElementById("tty-screen");
      if (screenElFallback) screenElFallback.textContent = "Terminal library unavailable.";
      return;
    }
    var shasum = root.dataset.shasum;
    var screenEl = document.getElementById("tty-screen");
    var statusEl = document.getElementById("tty-status");
    var playBtn = document.getElementById("tty-play");
    var restartBtn = document.getElementById("tty-restart");
    var speedEl = document.getElementById("tty-speed");
    var seekEl = document.getElementById("tty-seek");

    var records = null;
    var idx = 0;
    var playing = false;
    var timer = null;

    // disableStdin: this is playback, not an interactive shell -- nothing
    // this session's own real cowrie attacker typed should be re-typeable
    // here. screenReaderMode: xterm.js's own built-in accessibility tree
    // (an internally-managed aria-live region) replaces the manual
    // aria-live="polite" the old <pre>-based renderer needed.
    var term = new Terminal({
      cols: COLS, rows: ROWS, convertEol: true, disableStdin: true,
      cursorBlink: false, scrollback: 2000, screenReaderMode: true,
      fontFamily: "var(--font-mono, monospace)", fontSize: 13,
      theme: { background: "#16181d", foreground: "#e6e6e6" },
    });
    openTerminalUnderCSP(term, screenEl);

    function setStatus(msg) { statusEl.textContent = msg; }

    function reset() {
      term.reset();
      idx = 0;
      if (records && records.length) { seekEl.max = records.length - 1; seekEl.value = 0; }
    }

    function applyUpTo(target) {
      // Re-derive the whole screen from scratch on a seek/restart rather
      // than track incremental damage -- session recordings here are short
      // enough (seconds to a few minutes) that this is cheap, and it keeps
      // the terminal model impossible to desync from the record index.
      term.reset();
      for (var k = 0; k <= target && k < records.length; k++) term.write(records[k].data);
      idx = Math.min(target + 1, records.length);
      seekEl.value = idx - 1 >= 0 ? idx - 1 : 0;
    }

    function scheduleNext() {
      if (!playing || idx >= records.length) { playing = false; playBtn.textContent = "Replay"; return; }
      var rec = records[idx];
      var prevT = idx > 0 ? records[idx - 1].t : 0;
      var delay = Math.max(0, (rec.t - prevT) * 1000 / Number(speedEl.value || 1));
      timer = setTimeout(function () {
        term.write(rec.data);
        idx++;
        seekEl.value = idx - 1;
        scheduleNext();
      }, Math.min(delay, 3000));
    }

    playBtn.addEventListener("click", function () {
      if (!records || !records.length) return;
      if (playing) {
        playing = false;
        clearTimeout(timer);
        playBtn.textContent = "Resume";
        return;
      }
      if (idx >= records.length) applyUpTo(-1);
      playing = true;
      playBtn.textContent = "Pause";
      scheduleNext();
    });

    restartBtn.addEventListener("click", function () {
      playing = false;
      clearTimeout(timer);
      playBtn.textContent = "Replay";
      reset();
    });

    seekEl.addEventListener("input", function () {
      playing = false;
      clearTimeout(timer);
      playBtn.textContent = "Resume";
      applyUpTo(Number(seekEl.value));
    });

    setStatus("Loading recording…");
    fetch("/tty/" + encodeURIComponent(shasum) + ".json")
      .then(function (r) {
        if (!r.ok) throw new Error("HTTP " + r.status);
        return r.json();
      })
      .then(function (payload) {
        records = payload.records || [];
        if (!records.length) { setStatus("This recording has no replayable output."); return; }
        seekEl.max = records.length - 1;
        setStatus(records.length + " event(s), " + (payload.size_bytes || 0) + " bytes recorded.");
        playBtn.disabled = false;
        restartBtn.disabled = false;
        seekEl.disabled = false;
        applyUpTo(-1);
      })
      .catch(function (err) {
        setStatus("Could not load recording: " + err.message + " — try the raw/.cast download instead.");
      });
  }

  // #1268 "ask 2": a single-marker map for the Attacker replay tab's own
  // source IP -- deliberately NOT hp-app.js's initMaps() (that one drives
  // the overview page's clustered, drill-down-on-click origins layer
  // against a global, unfiltered GeoJSON feed; this is one fixed point,
  // no fetch, no clustering). Initialized lazily on first reveal of the
  // Attacker replay tab rather than eagerly on page load, since Leaflet
  // cannot size itself correctly inside a still-hidden [hidden] panel --
  // simpler to just not create the map until the container is visible
  // than to reuse activateDashboardTab's own invalidateSize() hook (which
  // only watches for the "leaflet-map" class this map deliberately
  // doesn't carry, to stay out of initMaps()'s own query).
  function initAttackerMap() {
    var mapDiv = document.getElementById("tty-attacker-map");
    if (!mapDiv || mapDiv.dataset.mapReady) return;
    mapDiv.dataset.mapReady = "1";
    if (!window.L) { mapDiv.textContent = "Interactive map library unavailable."; return; }
    var lat = Number(mapDiv.dataset.lat), lon = Number(mapDiv.dataset.lon);
    var tileURL = mapDiv.dataset.tileUrl;
    var attributionText = mapDiv.dataset.attribution || "OpenStreetMap contributors";
    var safeAttribution = document.createElement("span");
    safeAttribution.textContent = attributionText;
    var map = L.map(mapDiv, { minZoom: 1, maxZoom: 12 }).setView([lat, lon], 6);
    L.tileLayer(tileURL, {
      maxZoom: 19,
      attribution: '<a href="https://www.openstreetmap.org/copyright">' + safeAttribution.innerHTML + "</a>",
    }).addTo(map);
    L.marker([lat, lon]).addTo(map);
  }

  function initAttackerTab() {
    var tabButton = document.querySelector('[data-dashboard-tab="attacker"]');
    if (!tabButton) return;
    tabButton.addEventListener("click", initAttackerMap);
    // Direct-load with #attacker already the active tab (hp-app.js's own
    // activateDashboardTab runs before this, per document script order --
    // see this function's own comment on why that ordering is safe to
    // depend on): the click handler above never fires, so check the
    // panel's actual visibility once at startup too.
    var panel = document.getElementById("panel-attacker");
    if (panel && !panel.hidden) initAttackerMap();
  }

  document.addEventListener("DOMContentLoaded", init);
  document.addEventListener("DOMContentLoaded", initAttackerTab);
})();
