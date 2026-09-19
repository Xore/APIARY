# 3207-C1 — auth error chrome before a session exists

STATUS: DECIDED (user pick, 2026-09-18)

**DECIDED: Option A** — render auth error UI through the normal application route and bundled shadcn components. One styling system, no second stylesheet; pre-auth error pages depend on the application assets loading and may not render when they fail. Implement in the C1 continuation leg: move the error chrome into app routes; no standalone HTML, no separate stylesheet. OIDC success handling remains unchanged; failures redirect to the application error route.

The `/auth/login` and `/auth/callback` error responses are standalone server-generated HTML. They intentionally work when the application bundle cannot load and before a session exists. shadcn React components and semantic theme tokens require the bundled stylesheet and hydrated app; retaining the standalone fallback with inline styling violates this chunk's no-inline-styles/no-raw-hex rule.

- Option A: render error UI through the normal application route and bundled shadcn components. Gives consistent themed chrome, but errors may not render when assets fail to load.
- Option B: keep standalone HTML and serve a separately built, public semantic stylesheet for pre-auth pages. Retains fallback independence but requires an explicit asset and theme synchronization policy.

Choose the failure-mode contract for the pre-auth pages. No OIDC handler or auth error response was changed in this chunk.
