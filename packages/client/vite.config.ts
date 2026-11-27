import { existsSync, readdirSync } from 'node:fs'
import { join } from 'node:path'
import { defineConfig } from 'vite-plus'
import { playwright } from 'vite-plus/test/browser-playwright'

import { commands } from './tests/browser/rig'

// Playwright's own browser downloads do not run on NixOS, so the builds the system provides under
// `PLAYWRIGHT_BROWSERS_PATH` are taken when there are some, or the ones `WEBVPN_CHROMIUM` and `WEBVPN_FIREFOX` name
const build = (variable: string, prefix: string, ...path: string[]) => {
  if (process.env[variable]) return process.env[variable]
  const builds = process.env.PLAYWRIGHT_BROWSERS_PATH
  const found = builds && existsSync(builds) && readdirSync(builds).find((name) => name.startsWith(prefix))
  const executable = found && join(builds, found, ...path)
  return executable && existsSync(executable) ? executable : undefined
}
const chromium = () =>
  build('WEBVPN_CHROMIUM', 'chromium_headless_shell-', 'chrome-headless-shell-linux64', 'chrome-headless-shell')
const firefox = () => build('WEBVPN_FIREFOX', 'firefox-', 'firefox', 'firefox')

export default defineConfig({
  fmt: { semi: false, singleQuote: true },
  build: {
    outDir: 'build',
    target: 'esnext',
    emptyOutDir: true,
    minify: false,
    lib: { entry: { index: 'src/index.ts', stack: 'src/stack/index.ts' }, formats: ['es'] },
    rollupOptions: { external: [/^@banou\/ponyfill/] },
  },
  test: {
    projects: [
      {
        extends: true,
        test: {
          name: 'unit',
          include: ['tests/**/*.test.ts'],
          exclude: ['tests/**/*.browser.test.ts'],
          globalSetup: ['tests/stack/wasm.ts'],
        },
      },
      {
        extends: true,
        test: {
          name: 'browser',
          include: ['tests/**/*.browser.test.ts'],
          globalSetup: ['tests/stack/wasm.ts', 'tests/browser/rig.ts'],
          testTimeout: 30_000,
          browser: {
            enabled: true,
            headless: true,
            // the provider opens every page with `ignoreHTTPSErrors`, which is what lets `wss://` reach a relay
            // whose certificate is self-signed
            instances: [
              {
                browser: 'chromium',
                provider: playwright({ launchOptions: { executablePath: chromium(), args: ['--mute-audio'] } }),
              },
              {
                browser: 'firefox',
                provider: playwright({
                  launchOptions: { executablePath: firefox(), firefoxUserPrefs: { 'media.volume_scale': '0.0' } },
                }),
              },
            ],
            commands,
          },
        },
      },
    ],
  },
})
