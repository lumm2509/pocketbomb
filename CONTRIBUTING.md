# Contributing to PocketBomb

PocketBomb is a fork of [PocketBase](https://github.com/pocketbase/pocketbase). Contributions
are welcome, but the project is still pre-1.0 and the fork-specific behavior (OAuth2-only auth,
RBAC, GraphQL, applications, webhooks, LLM) is changing quickly.

For larger features or behavioral changes, please open an issue first so the design can be
discussed before you spend time on an implementation. Small bug fixes and documentation
improvements can go straight to a PR.

- [Prerequisites](#prerequisites)
- [Making changes in the Go code](#making-changes-in-the-go-code)
- [Making changes in the dashboard UI](#making-changes-in-the-dashboard-ui)

## Prerequisites

- Go 1.27+ (for making changes in the Go code)
- Node 24+ (for making changes in the dashboard UI)

If you haven't already, fork the repository and clone your fork so that you can work locally:

```sh
git clone https://github.com/your_username/pocketbomb.git
```

> [!IMPORTANT]
> It is recommended to create a new branch from master for each bugfix or feature.

## Making changes in the Go code

PocketBomb is distributed as a Go package, which means that in order to run the project you'll
have to create a Go `main` program that imports the package.

The repository already includes such a program, located in `examples/base`, which is also used
for the prebuilt executables and as the reference for the available plugins.

So, let's assume that you already made some changes in the PocketBomb Go code and you want to
run them:

1. Navigate to `examples/base`
2. Run `go run main.go serve`

This starts a web server on `http://localhost:8090` with the embedded prebuilt dashboard UI
from `ui/dist`.

The GraphQL read API is registered automatically at `/api/graphql`; `examples/base/main.go`
also contains a small `OnGraphQLRequest` hook example. GraphQL behavior is covered by the
tests in `apis/graphql*.go` and by the browser scenario `.tmp/e2e/scenarios/16_graphql.js`.

**Before making a PR, it is a good idea to:**

- Add unit/integration tests for your changes (we use the standard `testing` package):

  ```sh
  go test ./...

  # or using the Makefile
  make test
  ```

- Run the linter - **golangci** ([see how to install](https://golangci-lint.run/usage/install/#local-installation)):

  ```sh
  golangci-lint run -c ./golangci.yml ./...

  # or using the Makefile
  make lint
  ```

- If you change the JSVM bindings or public Go API, regenerate the JSVM types:

  ```sh
  make jstypes
  ```

## Making changes in the dashboard UI

The PocketBomb dashboard UI is a single-page application (SPA) built with Svelte and Vite.

To start the dashboard UI:

1. Navigate to the `ui` project directory
2. Run `npm install` to install the node dependencies
3. Start Vite's dev server:

   ```sh
   npm run dev
   ```

You can open the dashboard at `http://localhost:5173`.

Since the dashboard is a client-side application, you need the PocketBomb backend running in
the background (either manually running `examples/base/main.go` or a prebuilt executable).

> [!NOTE]
> By default, the dashboard expects the backend at `http://localhost:8090`, but you can change
> that by creating a new `ui/.env.development.local` file with a `PB_BACKEND_URL = YOUR_ADDRESS`
> variable inside it.

Every change you make in the dashboard UI should be automatically reflected in the browser
without reloading the page.

Once you are done with your changes, build the dashboard with `npm run build` so that it can be
embedded in the Go package, then submit your PR.
