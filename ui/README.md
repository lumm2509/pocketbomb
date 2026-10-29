PocketBomb dashboard UI
======================================================================

This is the PocketBomb dashboard UI (built with Shablon and Vite), a fork of the
PocketBase dashboard with GraphQL, OAuth2/OIDC, RBAC, applications and the other
fork-specific settings.

Although it could be used independently, it is intended to be embedded and extended
as part of the PocketBomb app executable (hence the `dist` directory and `embed.go` file).

> [!WARNING]
> The UI kit and extension APIs remain deliberately undocumented for the time being until a stable release is published.

## Development

Download the repository and run the appropriate console commands:

```sh
# install dependencies
npm install

# start a dev server with hot reload at localhost:5173
npm run dev

# or generate production ready bundle in dist/ directory
npm run build
```
