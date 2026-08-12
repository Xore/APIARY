// #612/#638: in-browser playback of a cowrie TTY session recording. No
// external terminal-emulator library (this stack avoids third-party CDN
// dependencies) -- instead a small, self-contained VT100 subset: cursor
// movement, erase-line/erase-display, and SGR colour/attribute codes. Good
// enough to read a typical cowrie session (linear prompt/output text with
// occasional colourised `ls`, backspace-edited input); it is not a full
// terminal emulator. Anything genuinely exotic still round-trips correctly
// through the ".cast" download, played with the real `asciinema` CLI.
(function () {
  "use strict";

  var COLS = 80, ROWS = 24;
  var ANSI_FG = { 30: "#000", 31: "#e05561", 32: "#8cc265", 33: "#d2b967", 34: "#4aa5f0", 35: "#c68ae2", 36: "#42c3ae", 37: "#e6e6e6", 90: "#666", 91: "#ff6b6b", 92: "#a5e075", 93: "#f0d97d", 94: "#6cb6ff", 95: "#e0a3ff", 96: "#67d9c9", 97: "#fff" };
  var ANSI_BG = { 40: "#000", 41: "#e05561", 42: "#8cc265", 43: "#d2b967", 44: "#4aa5f0", 45: "#c68ae2", 46: "#42c3ae", 47: "#e6e6e6", 100: "#666", 101: "#ff6b6b", 102: "#a5e075", 103: "#f0d97d", 104: "#6cb6ff", 105: "#e0a3ff", 106: "#67d9c9", 107: "#fff" };

  function blankRow() {
    var row = new Array(COLS);
    for (var i = 0; i < COLS; i++) row[i] = { ch: " ", style: null };
    return row;
  }

  function Screen() {
    this.rows = [blankRow()];
    this.cur = { r: 0, c: 0 };
    this.style = null; // {fg,bg,bold}
  }

  Screen.prototype.ensureRow = function (r) {
    while (this.rows.length <= r) this.rows.push(blankRow());
  };

  Screen.prototype.put = function (ch) {
    this.ensureRow(this.cur.r);
    if (this.cur.c >= COLS) { this.newline(); }
    this.rows[this.cur.r][this.cur.c] = { ch: ch, style: this.style };
    this.cur.c++;
  };

  Screen.prototype.newline = function () {
    this.cur.r++;
    this.cur.c = 0;
    this.ensureRow(this.cur.r);
  };

  Screen.prototype.eraseLineFromCursor = function () {
    this.ensureRow(this.cur.r);
    for (var c = this.cur.c; c < COLS; c++) this.rows[this.cur.r][c] = { ch: " ", style: null };
  };

  Screen.prototype.eraseLine = function () {
    this.ensureRow(this.cur.r);
    this.rows[this.cur.r] = blankRow();
  };

  Screen.prototype.eraseDisplayFromCursor = function () {
    this.eraseLineFromCursor();
    this.rows.length = this.cur.r + 1;
  };

  Screen.prototype.applySGR = function (params) {
    if (params.length === 0) params = [0];
    var style = this.style ? Object.assign({}, this.style) : null;
    params.forEach(function (p) {
      if (p === 0) { style = null; }
      else if (p === 1) { style = style || {}; style.bold = true; }
      else if (p === 39) { if (style) delete style.fg; }
      else if (p === 49) { if (style) delete style.bg; }
      else if (ANSI_FG[p]) { style = style || {}; style.fg = ANSI_FG[p]; }
      else if (ANSI_BG[p]) { style = style || {}; style.bg = ANSI_BG[p]; }
    });
    this.style = style;
  };

  // write() interprets one chunk of terminal output: plain text plus a
  // small CSI subset (cursor motion, EL/ED, SGR). Anything else recognized
  // as an escape sequence is consumed and discarded rather than left to
  // render as garbage characters.
  Screen.prototype.write = function (data) {
    var i = 0;
    while (i < data.length) {
      var ch = data[i];
      if (ch === "\r") { this.cur.c = 0; i++; continue; }
      if (ch === "\n") { this.newline(); i++; continue; }
      if (ch === "\b") { this.cur.c = Math.max(0, this.cur.c - 1); i++; continue; }
      if (ch === "\t") { this.cur.c = Math.min(COLS - 1, (Math.floor(this.cur.c / 8) + 1) * 8); i++; continue; }
      if (ch === "\x1b") {
        var m = /^\x1b\[([0-9;]*)([A-Za-z])/.exec(data.slice(i));
        if (m) {
          var params = m[1].length ? m[1].split(";").map(Number) : [];
          var final = m[2];
          if (final === "m") this.applySGR(params);
          else if (final === "K") { (params[0] === 2) ? this.eraseLine() : this.eraseLineFromCursor(); }
          else if (final === "J") { this.eraseDisplayFromCursor(); }
          else if (final === "A") { this.cur.r = Math.max(0, this.cur.r - (params[0] || 1)); }
          else if (final === "B") { this.cur.r = this.cur.r + (params[0] || 1); this.ensureRow(this.cur.r); }
          else if (final === "C") { this.cur.c = Math.min(COLS - 1, this.cur.c + (params[0] || 1)); }
          else if (final === "D") { this.cur.c = Math.max(0, this.cur.c - (params[0] || 1)); }
          else if (final === "H" || final === "f") { this.cur.r = Math.max(0, (params[0] || 1) - 1); this.cur.c = Math.max(0, (params[1] || 1) - 1); this.ensureRow(this.cur.r); }
          i += m[0].length;
          continue;
        }
        var osc = /^\x1b\][^\x07\x1b]*(\x07|\x1b\\)/.exec(data.slice(i));
        if (osc) { i += osc[0].length; continue; }
        // Unrecognized escape: skip just the ESC so we don't get stuck.
        i++;
        continue;
      }
      this.put(ch);
      i++;
    }
  };

  function blankCell(c) { return c.ch === " " && !(c.style && c.style.bg); }

  // Builds DOM nodes directly and sets colours/weight via individual
  // .style.* property assignment rather than a literal style="..." HTML
  // attribute -- CSP's style-src has no nonce/hash mechanism for inline
  // style attributes (a session's fg/bg/bold combinations are arbitrary,
  // not a small enumerable set a hash could cover), so building markup
  // with `style="..."` and injecting via innerHTML was silently blocked
  // by the dashboard's CSP (#646/#652). Per-property assignment on an
  // element's CSSStyleDeclaration is not subject to that restriction.
  function render(screen, el) {
    var lastRow = screen.rows.length - 1;
    while (lastRow > 0 && screen.rows[lastRow].every(blankCell)) lastRow--;
    var frag = document.createDocumentFragment();
    for (var r = 0; r <= lastRow; r++) {
      var row = screen.rows[r];
      var lastCol = COLS - 1;
      while (lastCol > 0 && blankCell(row[lastCol])) lastCol--;
      var i = 0;
      while (i <= lastCol) {
        var style = row[i].style;
        var j = i;
        var text = "";
        while (j <= lastCol && sameStyle(row[j].style, style)) { text += row[j].ch; j++; }
        if (style) {
          var span = document.createElement("span");
          if (style.fg) span.style.color = style.fg;
          if (style.bg) span.style.background = style.bg;
          if (style.bold) span.style.fontWeight = "bold";
          span.textContent = text;
          frag.appendChild(span);
        } else {
          frag.appendChild(document.createTextNode(text));
        }
        i = j;
      }
      if (r < lastRow) frag.appendChild(document.createTextNode("\n"));
    }
    el.textContent = "";
    el.appendChild(frag);
  }

  function sameStyle(a, b) {
    if (a === b) return true;
    if (!a || !b) return false;
    return a.fg === b.fg && a.bg === b.bg && a.bold === b.bold;
  }

  function init() {
    var root = document.getElementById("tty-viewer");
    if (!root) return;
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
    var screen = new Screen();

    function setStatus(msg) { statusEl.textContent = msg; }

    function draw() { render(screen, screenEl); }

    function reset() {
      screen = new Screen();
      idx = 0;
      draw();
      if (records && records.length) { seekEl.max = records.length - 1; seekEl.value = 0; }
    }

    function applyUpTo(target) {
      // Re-derive the whole screen from scratch on a seek/restart rather
      // than track incremental damage -- session recordings here are short
      // enough (seconds to a few minutes) that this is cheap, and it keeps
      // the terminal model impossible to desync from the record index.
      screen = new Screen();
      for (var k = 0; k <= target && k < records.length; k++) screen.write(records[k].data);
      idx = Math.min(target + 1, records.length);
      draw();
      seekEl.value = idx - 1 >= 0 ? idx - 1 : 0;
    }

    function scheduleNext() {
      if (!playing || idx >= records.length) { playing = false; playBtn.textContent = "Replay"; return; }
      var rec = records[idx];
      var prevT = idx > 0 ? records[idx - 1].t : 0;
      var delay = Math.max(0, (rec.t - prevT) * 1000 / Number(speedEl.value || 1));
      timer = setTimeout(function () {
        screen.write(rec.data);
        idx++;
        seekEl.value = idx - 1;
        draw();
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
