<p align="center">
    <a href="https://pocketbase.io" target="_blank" rel="noopener">
        <img src="https://i.imgur.com/aCBbjKx.png" alt="PocketBomb - backend in 1 file (PocketBase fork)" />
    </a>
</p>

<p align="center">
    <a href="https://pkg.go.dev/github.com/lumm2509/pocketbomb" target="_blank" rel="noopener"><img src="https://pkg.go.dev/badge/github.com/lumm2509/pocketbomb.svg" alt="Go package documentation" /></a>
    <a href="LICENSE.md" target="_blank" rel="noopener"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="MIT License" /></a>
    <img src="https://img.shields.io/badge/status-alpha-orange.svg" alt="Status: alpha" />
</p>

# PocketBomb

PocketBomb is a **fork of [PocketBase](https://github.com/pocketbase/pocketbase)** that keeps
the single-file Go backend model while extending it with a GraphQL read API, an
OAuth2/OIDC-only auth system with RBAC, API keys, applications/extensions, webhooks
and an LLM API.

The inherited PocketBase foundation is still there:

- embedded database (_SQLite_) with **realtime subscriptions**
- built-in **files and users management**
- convenient **dashboard UI**
- simple **REST-ish API**
- **Go framework/toolkit** and **JSVM** hooks/migrations

> [!WARNING]
> PocketBomb is under active development and is **not production-ready**.
> Full backward compatibility is not guaranteed before v1.0.0 and the fork may
> intentionally diverge from upstream PocketBase.

## Status of the fork

PocketBomb tracks the upstream PocketBase core but is **not a drop-in replacement**
for every upstream feature. The main differences at the moment are:

| Area | Status in PocketBomb |
|------|----------------------|
| GraphQL read API | Built-in, enabled by default at `/api/graphql` (queries only, Relay connections, introspection, depth/cost limits). |
| Auth | Vanilla PocketBase auth was replaced by **OAuth2/OIDC** (authorization code + PKCE, refresh rotation, token exchange, hosted login/consent pages). |
| Authorization | Real **RBAC** with the built-in `Owner` role, staff roles, per-collection/system permissions and scopes. |
| API keys | Public and private keys bound to OAuth2 clients, with allowed origins, buyer IP and permission ceilings. |
| Applications | Application catalog, manifests, installs/uninstalls, managed OAuth2 clients and dashboard extensions. |
| Other additions | Webhooks, LLM API, sessions/impersonation, staff management. |

Because of the auth changes, the **upstream auth/REST auth documentation does not apply
as-is**. Use this repository as the source of truth for the fork-specific behavior.

## Quick start

### Standalone executable

If a release is available for your platform, download it from the
[Releases page](https://github.com/lumm2509/pocketbomb/releases), extract the archive
and run `./pocketbase serve` in the extracted directory.

You can also build the example server locally:

```sh
go run ./examples/base serve
```

The server starts on `http://127.0.0.1:8090` with the embedded dashboard UI. On the
first run you will be asked to create the initial `Owner`.

The prebuilt executables are based on [`examples/base/main.go`](examples/base/main.go)
and include the JSVM plugin enabled by default.

### Use as a Go framework/toolkit

PocketBomb is distributed as a regular Go library package which allows you to build
your own custom app-specific business logic and still have a single portable executable.

Here is a minimal example that also hooks into the GraphQL API:

```go
package main

import (
    "log"

    "github.com/lumm2509/pocketbomb"
    "github.com/lumm2509/pocketbomb/core"
)

func main() {
    app := pocketbomb.New()

    app.OnServe().BindFunc(func(se *core.ServeEvent) error {
        // registers a new "GET /hello" route
        se.Router.GET("/hello", func(re *core.RequestEvent) error {
            return re.String(200, "Hello world!")
        })

        return se.Next()
    })

    // the GraphQL read API is registered automatically at /api/graphql
    // (see Settings -> GraphQL). This hook can inspect, rewrite or
    // short-circuit the incoming GraphQL operations.
    app.OnGraphQLRequest().BindFunc(func(e *core.GraphQLRequestEvent) error {
        app.Logger().Info("GraphQL request", "operation", e.OperationName)
        return e.Next()
    })

    if err := app.Start(); err != nil {
        log.Fatal(err)
    }
}
```

0. [Install Go 1.27+](https://go.dev/doc/install) (_if you haven't already_)
1. Save the file above as `main.go` in a new project directory.
2. Run `go mod init myapp && go mod tidy`.
3. Run `go run main.go serve`.
4. To build a statically linked executable, run `CGO_ENABLED=0 go build` and start it with `./myapp serve`.

### GraphQL API

The GraphQL API is **read-only** and is generated from the regular collections that are
reachable through the REST API (i.e. those with a public `listRule` or `viewRule`).
It is enabled by default and can be configured from **Settings -> GraphQL** in the dashboard.

- Endpoint: `GET|POST /api/graphql`
- Schema/introspection report: `GET /api/graphql/collections`
- Requests must identify a client with an API key (`X-PB-Public-Key` or
  `X-PB-Private-Key` + `X-PB-Buyer-IP`) or with an OAuth2 access token.
- Only queries are accepted; mutations and subscriptions are rejected.
- Default limits: max depth `10`, max cost `1000`, max page size `250`, max query size `32KB`,
  request timeout `10s`.

Example query using a public API key:

```sh
curl -X POST http://127.0.0.1:8090/api/graphql \
  -H "Content-Type: application/json" \
  -H "X-PB-Public-Key: YOUR_PUBLIC_KEY" \
  -d '{
    "query": "query { posts(first: 10, sort: \"-created\") { totalCount nodes { id title } pageInfo { hasNextPage endCursor } } }"
  }'
```

Collections are exposed using Relay-style connections (`FooConnection { edges { cursor node } nodes pageInfo }`),
a singular query (`post(id: ...)` or by a unique field) and a global `node(id: ...)` lookup.
The schema follows the collection names but may normalize them to valid GraphQL names; use
`GET /api/graphql/collections` (requires collections read permission) or introspection to
discover the generated types and fields.

The `OnGraphQLRequest` hook is available in Go and JSVM to inspect or modify the query,
variables and operation name, or to short-circuit the request.

### Building and running the repo example

1. [Install Go 1.27+](https://go.dev/doc/install) (_if you haven't already_)
2. Clone/download the repo
3. Navigate to `examples/base`
4. Run `CGO_ENABLED=0 go build` to build a binary for your current environment
   (_or target other platforms with `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build`;
   see https://go.dev/doc/install/source#environment_)
5. Start the executable with `./base serve`

Note that the supported build targets by the pure Go SQLite driver at the moment are:

| GOOS    | GOARCH  |
|---------|---------|
| darwin  | amd64   |
| darwin  | arm64   |
| freebsd | 386     |
| freebsd | amd64   |
| freebsd | arm     |
| freebsd | arm64   |
| linux   | 386     |
| linux   | amd64   |
| linux   | arm     |
| linux   | arm64   |
| linux   | loong64 |
| linux   | ppc64le |
| linux   | riscv64 |
| linux   | s390x   |
| netbsd  | amd64   |
| openbsd | amd64   |
| openbsd | arm64   |
| windows | 386     |
| windows | amd64   |
| windows | arm64   |

### Testing

PocketBomb comes with a mix of unit and integration tests. To run them, use the standard
`go test` command:

```sh
go test ./...

# or using the Makefile
make test
```

The fork-specific dashboard/auth/GraphQL flows are also covered by the browser end-to-end
suite in `.tmp/e2e` (kept out of version control). See `.tmp/e2e/README.md` for details.

## Documentation

- Upstream PocketBase docs: https://pocketbase.io/docs
  These are useful for the shared foundation (collections, records, files, realtime,
  JSVM, migrations), but **auth and some APIs differ in this fork**.
- GraphQL settings and the generated schema are documented in the dashboard
  (**Settings -> GraphQL** and the collection **GraphQL** tab).

## Security

If you discover a security vulnerability that is specific to PocketBomb, please report it
through the [fork's issue tracker](https://github.com/lumm2509/pocketbomb/issues) without
publishing exploit details. For vulnerabilities that also affect upstream PocketBase,
follow the [upstream security policy](https://github.com/pocketbase/pocketbase/security/policy).

## Contributing

PocketBomb is free and open source software licensed under the [MIT License](LICENSE.md).
You are free to do whatever you want with it, even offering it as a paid service.

Before opening a PR, please:

- read [CONTRIBUTING.md](CONTRIBUTING.md);
- add or update tests for your change (`go test ./...`, `make lint`);
- open an issue first for larger features or behavioral changes so the design can be discussed.

## License

[MIT](LICENSE.md). PocketBomb is a fork of PocketBase, which is also MIT licensed.
