import { existsSync, readdirSync } from 'node:fs'
import { join } from 'node:path'
import { defineConfig } from 'vite-plus'
import { playwright } from 'vite-plus/test/browser-playwright'

import { commands } from '../client/tests/browser/rig'

// Playwright's own Chromium download does not run on NixOS, so the headless shell of the Playwright builds the
// system provides is taken when there is one, or the one `WEBVPN_CHROMIUM` names
const chromium = () => {
  if (process.env.WEBVPN_CHROMIUM) return process.env.WEBVPN_CHROMIUM
  const builds = process.env.PLAYWRIGHT_BROWSERS_PATH
  const shell = builds && existsSync(builds) && readdirSync(builds).find((name) => name.startsWith('chromium_headless_shell-'))
  const path = shell && join(builds, shell, 'chrome-headless-shell-linux64', 'chrome-headless-shell')
  return path && existsSync(path) ? path : undefined
}

export default defineConfig({
  fmt: { semi: false, singleQuote: true },
  build: {
    outDir: 'build',
    target: 'esnext',
    emptyOutDir: true,
    minify: false,
    lib: { entry: { index: 'src/index.ts' }, formats: ['es'] },
    rollupOptions: { external: [/^@webvpn\/client/, 'buffer', 'events'] },
  },
  test: {
    // the client's source rather than its build, which a fresh checkout does not have
    alias: { '@webvpn/client': join(import.meta.dirname, '../client/src/index.ts') },
    projects: [
      {
        extends: true,
        test: {
          name: 'unit',
          include: ['tests/**/*.test.ts'],
          exclude: ['tests/**/*.browser.test.ts'],
          // the client's stack, which `tests/stack.test.ts` runs on, is built from its crate first
          globalSetup: ['../client/tests/stack/wasm.ts'],
        },
      },
      {
        extends: true,
        // found during the run, they would be optimized then and reload every page in flight
        optimizeDeps: { include: ['buffer', 'events'] },
        test: {
          name: 'browser',
          include: ['tests/**/*.browser.test.ts'],
          globalSetup: ['../client/tests/browser/rig.ts'],
          testTimeout: 30_000,
          browser: {
            enabled: true,
            headless: true,
            // the provider opens every page with `ignoreHTTPSErrors`, which is what lets `wss://` reach a relay
            // whose certificate is self-signed
            provider: playwright({ launchOptions: { executablePath: chromium(), args: ['--mute-audio'] } }),
            instances: [{ browser: 'chromium' }],
            commands,
          },
        },
      },
    ],
  },
})
