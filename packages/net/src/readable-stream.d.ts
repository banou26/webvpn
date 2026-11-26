// readable-stream ships no types, and its classes follow Node's stream module, whose types are taken here
declare module 'readable-stream' {
  export { Duplex } from 'node:stream'
}
