// Measures one TCP download through the stack's whole glue (tests/stack/throughput.ts), in Node and in headless
// Chromium, and prints megabits per second. A measurement to quote, not a test: nothing here fails on a slow machine.
// Usage: node scripts/throughput.ts [megabytes]
import { execFileSync } from 'node:child_process'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { chromium } from 'playwright'
import { build } from 'vite'

type Measure = (megabytes: number) => Promise<{ megabytes: number, seconds: number, mbps: number }>

const megabytes = Number(process.argv[2] ?? 64)
execFileSync(process.execPath, [join(import.meta.dirname, 'wasm.ts')], { stdio: 'inherit' })
const output = await build({
  configFile: false,
  logLevel: 'silent',
  build: {
    write: false,
    target: 'esnext',
    minify: false,
    lib: { entry: join(import.meta.dirname, '../tests/stack/throughput.ts'), formats: ['es'], fileName: 'throughput' },
  },
})
const [{ output: [bundle] }] = [output].flat() as unknown as [{ output: [{ code: string }] }]
const directory = mkdtempSync(join(tmpdir(), 'webvpn-throughput-'))
const report = (where: string, { megabytes, seconds, mbps }: Awaited<ReturnType<Measure>>) =>
  console.log(`${where}: ${megabytes} MiB in ${seconds.toFixed(2)} s, ${mbps.toFixed(0)} Mbit/s`)

try {
  const file = join(directory, 'throughput.mjs')
  writeFileSync(file, bundle.code)
  const { measure } = await import(pathToFileURL(file).href) as { measure: Measure }
  report('Node', await measure(megabytes))

  const browser = await chromium.launch({ headless: true, args: ['--mute-audio'] })
  try {
    const page = await browser.newPage()
    await page.addScriptTag({ content: bundle.code, type: 'module' })
    await page.waitForFunction(() => 'measure' in globalThis)
    const result = await page.evaluate((size) => (globalThis as unknown as { measure: Measure }).measure(size), megabytes)
    report(`Chromium ${browser.version()}`, result)
  } finally {
    await browser.close()
  }
} finally {
  rmSync(directory, { recursive: true, force: true })
}
