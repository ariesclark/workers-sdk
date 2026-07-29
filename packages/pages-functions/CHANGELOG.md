# @cloudflare/pages-functions

## 0.1.0

### Minor Changes

- [#14785](https://github.com/cloudflare/workers-sdk/pull/14785) [`5e6556a`](https://github.com/cloudflare/workers-sdk/commit/5e6556a0c788679b6ac149ba3018a2cfd7cc73e9) Thanks [@dario-piotrowicz](https://github.com/dario-piotrowicz)! - Publish helpers for compiling Pages Functions directories into Workers bundle

  Provides both a programmatic API and a CLI (`pages-functions build`) for converting a Cloudflare Pages `functions/` directory into a Cloudflare Workers bundle:

  ```sh
  npx @cloudflare/pages-functions build ./functions --outdir ./dist
  ```

  The package compiles the Worker and its auxiliary modules, but does not deploy them or generate deployment configuration. Consumers must provide the appropriate Wrangler configuration, including the selected fallback service binding (`ASSETS` by default) when applicable.
