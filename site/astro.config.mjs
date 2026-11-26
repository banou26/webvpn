import starlight from '@astrojs/starlight'
import { defineConfig } from 'astro/config'
import { description, title } from './src/site.mjs'

export default defineConfig({
  site: 'https://webvpn.dev',
  integrations: [
    starlight({
      title,
      description,
      favicon: '/favicon.svg',
      sidebar: [
        { label: 'What WebVPN is', slug: 'docs' },
        { label: 'How it works', slug: 'docs/how-it-works' },
        { label: 'The protocol', slug: 'docs/protocol' },
        { label: 'Using it from an app', slug: 'docs/using' },
        {
          label: 'The public relays',
          items: [
            { label: 'Relays', slug: 'docs/relays' },
            { label: 'What the relay keeps', slug: 'docs/what-the-relay-keeps' },
            { label: 'Network operators and rights holders', slug: 'docs/network-operators' },
          ],
        },
      ],
    }),
  ],
})
