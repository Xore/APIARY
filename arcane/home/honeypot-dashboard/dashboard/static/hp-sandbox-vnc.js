// Read-only live view of the Windows sandbox's detonation VM (#805).
// Wires vendored noVNC (static/vendor/novnc/core/rfb.js) to the target
// canvas and the bridge WebSocket URL sandbox_vnc.html's data attributes
// carry. viewOnly=true is client-side belt-and-suspenders: the real
// enforcement is the bridge's own RFB message filtering
// (sandbox/windows/vnc-bridge/server.py), which drops KeyEvent/
// PointerEvent/ClientCutText before they ever reach the VM regardless of
// what any browser-side code does or fails to do.
import RFB from "/static/vendor/novnc/core/rfb.js";

const root = document.querySelector("[data-vnc-root]");
if (root) {
  const status = root.querySelector("[data-vnc-status]");
  const target = root.querySelector("[data-vnc-target]");
  const url = root.dataset.vncUrl;

  const setStatus = (text, state) => {
    if (status) status.textContent = text;
    target.querySelector("[data-vnc-loading]")?.remove();
    target.setAttribute("aria-busy", "false");
    root.dataset.vncState = state;
    if (state !== "connected" && !target.querySelector("canvas") && !target.querySelector("[data-vnc-state-message]")) {
      const message = document.createElement("p");
      message.className = "empty";
      message.dataset.vncStateMessage = "";
      message.textContent = text;
      target.appendChild(message);
    }
  };

  const rfb = new RFB(target, url, {shared: true});
  rfb.viewOnly = true;
  rfb.scaleViewport = true;

  rfb.addEventListener("connect", () => {
    setStatus("Connected — view only.", "connected");
  });
  rfb.addEventListener("disconnect", e => {
    setStatus(e.detail && e.detail.clean
      ? "Disconnected."
      : "Connection lost — the detonation may have finished, or the bridge is unreachable.", "disconnected");
  });
  rfb.addEventListener("credentialsrequired", () => setStatus("This bridge does not support authenticated VNC sessions.", "error"));
  rfb.addEventListener("securityfailure", e => setStatus("Security handshake failed: " + (e.detail && e.detail.reason || "unknown reason"), "error"));
}
