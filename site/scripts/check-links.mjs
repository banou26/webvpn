// Every href and src in the built site that stays on the site must name a file in dist, and a #fragment must name an id on that page.
import { readdirSync, readFileSync, existsSync, statSync } from 'node:fs'
import { join, dirname, resolve } from 'node:path'

const root = resolve(process.argv[2] ?? 'dist')

const htmlFiles = dir => readdirSync(dir, { withFileTypes: true }).flatMap(entry => {
  const path = join(dir, entry.name)
  return entry.isDirectory() ? htmlFiles(path) : path.endsWith('.html') ? [path] : []
})

const targetFile = path => [path, join(path, 'index.html'), `${path}.html`]
  .find(candidate => existsSync(candidate) && statSync(candidate).isFile())

const ids = file => new Set([...readFileSync(file, 'utf8').matchAll(/\sid="([^"]+)"/g)].map(match => match[1]))

let checked = 0
const broken = []
for (const file of htmlFiles(root)) {
  const html = readFileSync(file, 'utf8')
  for (const [, link] of html.matchAll(/\s(?:href|src)="([^"]*)"/g)) {
    if (/^(?:[a-z]+:|\/\/)/i.test(link)) continue
    const [withQuery, fragment] = link.split('#')
    const path = withQuery.split('?')[0]
    const target = path === '' ? file : targetFile(path.startsWith('/') ? join(root, path) : join(dirname(file), path))
    checked += 1
    if (!target) broken.push(`${file.slice(root.length)}: ${link}`)
    else if (fragment && target.endsWith('.html') && !ids(target).has(decodeURIComponent(fragment))) broken.push(`${file.slice(root.length)}: ${link} (no such id)`)
  }
}

console.log(`${checked} internal links checked, ${broken.length} broken`)
for (const line of broken) console.log(`  ${line}`)
process.exit(broken.length || !checked ? 1 : 0)
