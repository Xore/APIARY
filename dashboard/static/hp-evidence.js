/* Evidence viewer — overlay for raw analysis output.
 *
 * Strings dumps, stdout/stderr, socket tables, and hex previews are evidence
 * an investigator reads deliberately, not while scanning a page. Rendering
 * them inline pushed the findings that matter off the screen. A page marks
 * such a block:
 *
 *   <button data-hp-evidence="pe-strings">Extracted strings (1 284)</button>
 *   <div hidden data-hp-evidence-body="pe-strings"
 *        data-hp-evidence-title="Extracted Windows strings"
 *        data-hp-evidence-note="Printable sequences, deduplicated.">
 *     …the block…
 *   </div>
 *
 * The body stays in the server-rendered HTML — nothing is fetched, so the
 * evidence is in the page the operator already has, and a run with no JavaScript
 * still ships the complete record.
 *
 * Behavior follows the shared modal contract (Xore/theme docs/MODALS.md):
 * application-managed overlay, inert + aria-hidden when closed, focus moved in
 * on open and restored on close, focus trapped while open, and Escape closing
 * only the deepest layer — it yields to an open destructive confirmation.
 */
(() => {
  "use strict";

  const backdrop = document.getElementById("hp-evidence-backdrop");
  const modal = document.getElementById("hp-evidence-modal");
  if (!backdrop || !modal) return;

  const title = modal.querySelector("[data-hp-evidence-title-target]");
  const note = modal.querySelector("[data-hp-evidence-note-target]");
  const body = modal.querySelector("[data-hp-evidence-body-target]");
  const closeButton = modal.querySelector("[data-hp-evidence-close]");
  const search = modal.querySelector("[data-hp-evidence-search]");

  let restoreFocus = null;
  let isOpen = false;

  const focusable = () => Array.from(modal.querySelectorAll(
    'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
  )).filter(element => !element.hidden && element.offsetParent !== null);

  /* Filtering operates on whole lines of a <pre> and on table rows, which is
     what these blocks actually are. Anything else is left untouched. */
  const filterBody = query => {
    const needle = query.trim().toLowerCase();
    let shown = 0;
    let total = 0;

    body.querySelectorAll("tbody tr").forEach(row => {
      total++;
      const match = !needle || row.textContent.toLowerCase().includes(needle);
      row.hidden = !match;
      if (match) shown++;
    });

    body.querySelectorAll("pre").forEach(pre => {
      if (pre.dataset.hpLines === undefined) pre.dataset.hpLines = pre.textContent;
      const lines = pre.dataset.hpLines.split("\n");
      total += lines.length;
      if (!needle) {
        pre.textContent = pre.dataset.hpLines;
        shown += lines.length;
        return;
      }
      const kept = lines.filter(line => line.toLowerCase().includes(needle));
      shown += kept.length;
      pre.textContent = kept.join("\n");
    });

    const counter = modal.querySelector("[data-hp-evidence-count]");
    if (counter) counter.textContent = needle ? `${shown} of ${total} lines` : "";
  };

  function open(trigger) {
    const key = trigger.dataset.hpEvidence;
    const source = document.querySelector(`[data-hp-evidence-body="${CSS.escape(key)}"]`);
    if (!source) return;

    restoreFocus = trigger;
    title.textContent = source.dataset.hpEvidenceTitle || trigger.textContent.trim();
    modal.setAttribute("aria-label", title.textContent);
    if (note) {
      note.textContent = source.dataset.hpEvidenceNote || "";
      note.hidden = !source.dataset.hpEvidenceNote;
    }
    // Clone: the source stays in the page so the evidence survives a reload
    // and remains present without JavaScript.
    body.replaceChildren(...Array.from(source.childNodes, node => node.cloneNode(true)));
    if (search) {
      search.value = "";
      // Only offer filtering where it means something.
      search.closest("[data-hp-evidence-search-field]").hidden =
        !body.querySelector("pre") && !body.querySelector("tbody tr");
    }
    filterBody("");

    backdrop.inert = false;
    backdrop.setAttribute("aria-hidden", "false");
    backdrop.classList.add("open");
    modal.inert = false;
    modal.setAttribute("aria-hidden", "false");
    modal.classList.add("open");
    isOpen = true;
    closeButton?.focus();
  }

  function close() {
    if (!isOpen) return;
    isOpen = false;
    modal.classList.remove("open");
    modal.setAttribute("aria-hidden", "true");
    modal.inert = true;
    backdrop.classList.remove("open");
    backdrop.setAttribute("aria-hidden", "true");
    backdrop.inert = true;
    body.replaceChildren();
    if (restoreFocus?.isConnected) restoreFocus.focus();
    restoreFocus = null;
  }

  document.addEventListener("click", event => {
    const trigger = event.target.closest("[data-hp-evidence]");
    if (!trigger) return;
    event.preventDefault();
    open(trigger);
  });
  closeButton?.addEventListener("click", close);
  backdrop.addEventListener("click", close);
  search?.addEventListener("input", () => filterBody(search.value));

  document.addEventListener("keydown", event => {
    if (!isOpen) return;
    // A destructive confirmation opened above this viewer owns Escape.
    if (window.HoneypotModals?.isOpen()) return;
    if (event.key === "Escape") {
      event.preventDefault();
      event.stopImmediatePropagation();
      close();
      return;
    }
    if (event.key !== "Tab") return;
    const controls = focusable();
    if (!controls.length) return;
    const first = controls[0];
    const last = controls[controls.length - 1];
    if (event.shiftKey && (document.activeElement === first || !modal.contains(document.activeElement))) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  });

  window.HoneypotEvidence = Object.freeze({ close, isOpen: () => isOpen });
})();
