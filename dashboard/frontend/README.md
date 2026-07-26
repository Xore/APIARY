# Typed frontend boundary

This directory owns the browser-facing API contracts. The production image
serves the committed `static/hp-api.js` bundle, so Node.js is not required at
runtime. Run `npm ci`, `npm run typecheck`, and `npm run build` after changing
the TypeScript API client. Server-rendered HTML remains the resilient initial
render while AdminLTE progressively adds live navigation and investigation
controls.
