// The protocol page is spec/protocol.md, the one source: its heading becomes the page's title, the rest is unchanged.
import { readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

const site = join(import.meta.dirname, '..')
const [heading, ...body] = readFileSync(join(site, '../spec/protocol.md'), 'utf8').split('\n')
if (!heading.startsWith('# ')) throw new Error('spec/protocol.md must start with its title')

const frontMatter = [
  '---',
  `title: ${JSON.stringify(heading.slice(2))}`,
  'description: Every frame, code and carrier of the WebVPN protocol.',
  '---',
]
writeFileSync(join(site, 'src/content/docs/docs/protocol.md'), [...frontMatter, ...body].join('\n'))
