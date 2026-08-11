// APIARY-owned overlay for the vendored Rev·Deck chat composer -- see
// wsgi_proxyfix.py's own doc comment for why this lives outside webui/ and
// how it gets onto the page (an after_request hook injects the <script>
// tag; this file itself is bind-mounted into webui/static/js/ and served
// by Flask's own static handler, same as composer.js/app.js).
//
// Adds a "Presets" button to the chat composer row (#chat-form's
// .composer__row, next to #chat-send) with a short list of common
// reverse-engineering starting prompts. Picking one fills #chat-input and
// clicks the real #chat-send button -- not a duplicate submit path -- so
// every existing guard (disabled state while a job is running, the
// required-target check for workflows like attack_surface_triage,
// whatever mode/workflow/budget is currently selected) applies exactly as
// if the operator had typed the prompt and clicked Send themselves.
(() => {
  "use strict";

  const PRESETS = [
    {
      label: "Summarize this program",
      prompt: "Give a high-level summary of what this program does, based on its imports, strings, and overall structure.",
    },
    {
      label: "Find the most suspicious function",
      prompt: "Identify the single most suspicious function in this program and explain exactly why it stands out.",
    },
    {
      label: "Network behavior",
      prompt: "List every function or import related to network communication and explain what data, if any, this program appears to send or receive.",
    },
    {
      label: "Anti-analysis checks",
      prompt: "Check for anti-debugging, anti-VM, or other anti-analysis techniques and point to the specific evidence for each one you find.",
    },
    {
      label: "Persistence mechanisms",
      prompt: "Identify any mechanism this program uses to persist across reboots or maintain access -- registry run keys, scheduled tasks, services, startup folders, or anything similar.",
    },
    {
      label: "Suspicious strings",
      prompt: "List the strings in this program that look like URLs, IP addresses, file paths, or credentials, and explain what each one is likely used for.",
    },
  ];

  function init() {
    const form = document.getElementById("chat-form");
    const input = document.getElementById("chat-input");
    const sendBtn = document.getElementById("chat-send");
    const row = form && form.querySelector(".composer__row");
    if (!form || !input || !sendBtn || !row) return;

    const wrap = document.createElement("div");
    wrap.className = "hp-preset-wrap";
    wrap.style.position = "relative";

    const toggle = document.createElement("button");
    toggle.type = "button";
    toggle.id = "hp-preset-toggle";
    toggle.className = "btn";
    toggle.textContent = "Presets";
    toggle.setAttribute("aria-haspopup", "true");
    toggle.setAttribute("aria-expanded", "false");

    const menu = document.createElement("div");
    menu.id = "hp-preset-menu";
    menu.setAttribute("role", "menu");
    menu.hidden = true;
    menu.style.cssText =
      "position:absolute; bottom:100%; left:0; margin-bottom:6px; " +
      "background:var(--surface-1, #1e1e1e); border:1px solid var(--border-strong, #444); " +
      "border-radius:8px; padding:4px; min-width:260px; max-width:360px; z-index:30; " +
      "box-shadow:0 8px 24px rgba(0,0,0,.4);";

    const openMenu = () => {
      menu.hidden = false;
      toggle.setAttribute("aria-expanded", "true");
    };
    const closeMenu = () => {
      menu.hidden = true;
      toggle.setAttribute("aria-expanded", "false");
    };

    PRESETS.forEach(preset => {
      const item = document.createElement("button");
      item.type = "button";
      item.className = "hp-preset-item";
      item.setAttribute("role", "menuitem");
      item.textContent = preset.label;
      item.title = preset.prompt;
      item.style.cssText =
        "display:block; width:100%; text-align:left; background:none; border:0; " +
        "padding:8px 10px; cursor:pointer; color:inherit; font:inherit; border-radius:5px;";
      item.addEventListener("mouseenter", () => { item.style.background = "var(--surface-2, #2c2c2c)"; });
      item.addEventListener("mouseleave", () => { item.style.background = "none"; });
      item.addEventListener("click", () => {
        input.value = preset.prompt;
        // Several other listeners in this app (autosize, submit-enable
        // state) react to real user input, not a bare .value assignment --
        // dispatch the same event a keystroke would fire.
        input.dispatchEvent(new Event("input", {bubbles: true}));
        closeMenu();
        input.focus();
        if (!sendBtn.disabled) sendBtn.click();
      });
      menu.appendChild(item);
    });

    toggle.addEventListener("click", e => {
      e.preventDefault();
      if (menu.hidden) openMenu();
      else closeMenu();
    });
    document.addEventListener("click", e => {
      if (!wrap.contains(e.target)) closeMenu();
    });
    document.addEventListener("keydown", e => {
      if (e.key === "Escape") closeMenu();
    });

    wrap.appendChild(toggle);
    wrap.appendChild(menu);
    row.insertBefore(wrap, sendBtn);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
