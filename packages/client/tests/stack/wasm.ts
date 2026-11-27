// the stack's module is built from the crate before any test imports it
import { buildWasm } from '../../scripts/wasm'

export default () => buildWasm()
