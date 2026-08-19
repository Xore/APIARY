// @novnc/novnc ships no TypeScript declarations of its own. Minimal ambient
// type covering only what sandbox.vnc.tsx actually uses — see
// node_modules/@novnc/novnc/core/rfb.js for the full (untyped) surface.
declare module '@novnc/novnc' {
  export default class RFB extends EventTarget {
    constructor(target: HTMLElement, urlOrChannel: string, options?: { shared?: boolean; credentials?: Record<string, string> })
    viewOnly: boolean
    scaleViewport: boolean
    disconnect(): void
  }
}
