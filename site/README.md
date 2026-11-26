# webvpn.dev

The WebVPN site, built with Astro Starlight. Private behind Cloudflare Access until the owner says to make it public.

```sh
npm install
npm run build        # static site in dist/
npm run check-links  # every link inside dist/ resolves, fragments included
npx wrangler deploy  # no build runs on push
```

- The home page is `src/pages/index.astro`.
- The docs pages, served under `/docs/`, are in `src/content/docs/docs/`.
- The protocol page is `../spec/protocol.md`, copied in by `scripts/sync-spec.mjs` before every build and dev run.
