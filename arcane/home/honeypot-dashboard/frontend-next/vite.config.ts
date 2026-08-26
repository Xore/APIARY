import { resolve } from 'node:path'
import { defineConfig } from 'vite'

import { tanstackStart } from '@tanstack/react-start/plugin/vite'

import viteReact from '@vitejs/plugin-react'
import { nitro } from 'nitro/vite'

const config = defineConfig({
  resolve: { tsconfigPaths: true },
  plugins: [
    // #2183: the service-token boot gate, explicit rather than scan-dir
    // discovered so nothing about this deployment rides on nitro's
    // convention for where plugins live. Runs while the server bundle
    // boots; see server/plugins/service-token-gate.ts.
    nitro({
      plugins: [resolve(import.meta.dirname ?? '.', 'server/plugins/service-token-gate.ts')],
      rollupConfig: { external: [/^@sentry\//] },
    }),

    tanstackStart(),
    viteReact(),
  ],
})

export default config
