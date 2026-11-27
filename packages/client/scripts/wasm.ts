// Builds webvpn-stack to WebAssembly and writes it, as base64, into the module `src/stack/wasm.js`, which the build
// bundles into `stack.js` and the tests import. The file is written only when its bytes change, so a watcher does not
// rebuild for nothing.
import { execFileSync } from 'node:child_process'
import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

const root = join(import.meta.dirname, '../../..')
const out = join(import.meta.dirname, '../src/stack/wasm.js')

export const buildWasm = () => {
  execFileSync('cargo', ['build', '--release', '--target', 'wasm32-unknown-unknown', '-p', 'webvpn-stack'], {
    cwd: root,
    stdio: 'inherit',
  })
  const bytes = readFileSync(join(root, 'target/wasm32-unknown-unknown/release/webvpn_stack.wasm'))
  const module = `export default '${bytes.toString('base64')}'\n`
  if (!existsSync(out) || readFileSync(out, 'utf8') !== module) writeFileSync(out, module)
}

if (process.argv[1] === import.meta.filename) buildWasm()
