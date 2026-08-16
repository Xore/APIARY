/* Ghidra Rev·Deck markdown rendering (#1285/#1286).
 *
 * AI-generated content -- RevDeck's one-shot triage Answer, and
 * assistant/tool messages in its mirrored chat transcript -- reaches this
 * page as server-escaped plain text: html/template auto-escapes it into a
 * text node exactly like every other untrusted field this dashboard
 * renders, so a run with this script disabled still shows the literal,
 * safe (if unstyled) text. This script adds the typographic layer on top:
 * parse that plain text as markdown with marked.js, then sanitize the
 * result with DOMPurify before it ever reaches innerHTML, so a malware
 * sample's attacker-influenced strings -- which end up here filtered
 * through the model's own reasoning, not written by this dashboard's
 * operators -- cannot smuggle a script or event handler through the
 * report.
 *
 * render() walks every [data-markdown] node currently in the document,
 * including the hidden evidence-modal body ui/ghidra.html renders the
 * chat transcript into -- hp-evidence.js's open() clones that node's
 * *current* children when a user opens the modal, so rendering it here
 * first means the clone is already-sanitized HTML by the time that
 * happens; no coupling to hp-evidence.js is needed.
 *
 * #1288/#1285/#1286 shell+hydrate: the detail page's [data-markdown]
 * nodes don't exist yet at initial script load -- they arrive later, once
 * hp-ghidra-report.js fetches and swaps in the "GET /ghidra/{sha}/fragment"
 * response -- so this is exposed as window.HoneypotGhidraMarkdown.render()
 * for that swap to call, rather than only ever running once up front.
 */
(() => {
  "use strict";
  if (!window.marked || !window.DOMPurify) return;

  marked.use({ breaks: true, gfm: true });

  const SANITIZE_OPTS = {
    ALLOWED_TAGS: [
      "p", "br", "strong", "em", "del", "code", "pre",
      "ul", "ol", "li", "h1", "h2", "h3", "h4", "h5", "h6",
      "blockquote", "a", "hr", "table", "thead", "tbody", "tr", "th", "td",
    ],
    ALLOWED_ATTR: ["href"],
    // Deliberately narrower than DOMPurify's own default: only an
    // absolute http(s) URL survives, not a relative path, "#anchor", or a
    // mailto:/data: URI -- this content never needs to link anywhere but
    // out to the web, and a narrower allowlist is less to get wrong.
    ALLOWED_URI_REGEXP: /^https?:\/\//i,
  };

  function sentenceBoundaries(text) {
    if (typeof Intl?.Segmenter === "function") {
      const segmenter = new Intl.Segmenter(undefined, { granularity: "sentence" });
      return Array.from(segmenter.segment(text), part => part.index + part.segment.trimEnd().length)
        .filter(end => /\S/.test(text.slice(end)));
    }
    const ends = [];
    const pattern = /[.!?]+(?:["')\]]+)?(?=\s+\S)/g;
    for (const match of text.matchAll(pattern)) ends.push(match.index + match[0].length);
    return ends;
  }

  // Add visual sentence breaks only after Markdown has been parsed and
  // sanitized. Working on text nodes preserves headings, lists, links and
  // emphasis exactly as marked produced them, while code/pre content is kept
  // byte-for-byte intact. A reverse-order insertion keeps all recorded text
  // offsets stable as <br> nodes are added.
  function addSentenceBreaks(root) {
    root.querySelectorAll("p, li").forEach(block => {
      const nodes = [];
      const walker = document.createTreeWalker(block, NodeFilter.SHOW_TEXT);
      while (walker.nextNode()) {
        const node = walker.currentNode;
        if (node.parentElement?.closest("code, pre")) continue;
        if (node.parentElement?.closest("p, li") !== block) continue;
        nodes.push(node);
      }
      const text = nodes.map(node => node.data).join("");
      const boundaries = sentenceBoundaries(text);
      for (let i = boundaries.length - 1; i >= 0; i--) {
        let remaining = boundaries[i];
        for (const node of nodes) {
          if (remaining <= node.data.length) {
            const range = document.createRange();
            range.setStart(node, remaining);
            range.collapse(true);
            range.insertNode(document.createElement("br"));
            break;
          }
          remaining -= node.data.length;
        }
      }
    });
  }

  function render() {
    document.querySelectorAll("[data-markdown]").forEach(el => {
      const html = DOMPurify.sanitize(marked.parse(el.textContent), SANITIZE_OPTS);
      el.innerHTML = html;
      if (el.classList.contains("hp-ai-report__body")) addSentenceBreaks(el);
      el.querySelectorAll("a[href]").forEach(a => {
        a.target = "_blank";
        a.rel = "noopener noreferrer";
      });
    });
  }

  render();
  window.HoneypotGhidraMarkdown = Object.freeze({ render });
})();
