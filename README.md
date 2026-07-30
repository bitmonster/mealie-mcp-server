# Mealie MCP Server

A security-conscious [Model Context Protocol](https://modelcontextprotocol.io/) server for self-hosted [Mealie](https://mealie.io/) instances.

It exposes recipe search and import, shopping lists, meal plans, organizers, ingredient parsing, OCR helpers, recipe images/assets, Chefkoch lookup, and a guarded bridge to non-sensitive Mealie OpenAPI operations.

> Community project. Not affiliated with or endorsed by Mealie.

## Security defaults

- **Read-only by default:** mutations require `MEALIE_MCP_ALLOW_MUTATIONS=true`.
- **Fail-closed scopes:** no write is allowed unless its path matches an explicit scope.
- **Explicit confirmation:** every helper that persists data and every generic write requires `confirmed_by_user=true`.
- **Sensitive API denylist:** admin, authentication, user, group, invitation, webhook, and household self-service endpoints remain blocked even when mutations are enabled.
- **Outbound fetches off by default:** URL imports and remote file sources require separate opt-in flags in addition to mutation scopes.
- **SSRF protection:** enabled remote sources must resolve to public HTTP(S) addresses; loopback, private, link-local, and other non-public destinations are rejected.
- **Local-file confinement:** multipart uploads may only read from the MCP data directory or explicitly configured local roots.
- **Credential redaction:** configured tokens and passwords are removed from reported errors.
- **Bounded work:** JSON/OpenAPI responses, local/remote sources, downloads, image pixels, pagination, and OCR runtime have limits.
- **Transport safety:** remote Mealie origins require HTTPS, and authenticated Mealie requests reject redirects.

Review [SECURITY.md](SECURITY.md) before enabling writes.

## Requirements

- Python 3.11+
- [uv](https://docs.astral.sh/uv/)
- A reachable Mealie instance (tested against Mealie OpenAPI v3.21.0)
- A Mealie long-lived API token, recommended
- Optional: Tesseract for OCR (`tesseract-ocr` plus the desired language packs)

## Quick start

```bash
git clone https://github.com/bitmonster/mealie-mcp-server.git
cd mealie-mcp-server
uv sync --frozen
chmod +x run_mealie_mcp.sh
```

Create a long-lived token in Mealie under **Profile → API tokens**. Pass it through your MCP client environment; do not put it in source control.

### Hermes Agent

```yaml
mcp_servers:
  mealie:
    command: /absolute/path/to/mealie-mcp-server/run_mealie_mcp.sh
    env:
      MEALIE_BASE_URL: http://localhost:9000
      MEALIE_PUBLIC_URL: https://mealie.example.com
      MEALIE_API_TOKEN: "[REDACTED]"
      MEALIE_MCP_ALLOW_MUTATIONS: "false"
      MEALIE_MCP_MUTATION_SCOPE: none
      MEALIE_MCP_ALLOW_URL_IMPORTS: "false"
      MEALIE_MCP_ALLOW_REMOTE_SOURCES: "false"
```

Restart Hermes after changing MCP configuration, then run:

```bash
hermes mcp test mealie
```

### Generic stdio MCP client

Configure the command as:

```text
/absolute/path/to/mealie-mcp-server/run_mealie_mcp.sh
```

Set the environment variables shown in `.env.example`. The server reserves stdout for MCP JSON-RPC and writes startup errors to stderr.

## Authentication

Preferred:

```text
MEALIE_API_TOKEN=[REDACTED]
```

Optional fallback for local testing:

```text
MEALIE_USERNAME=[REDACTED]
MEALIE_PASSWORD=[REDACTED]
```

The fallback performs a normal `/api/auth/token` login and caches the short-lived token in memory. Do not embed credentials in the repository or starter script.

## Mutation scopes

Mutations require both:

```text
MEALIE_MCP_ALLOW_MUTATIONS=true
MEALIE_MCP_MUTATION_SCOPE=<comma-separated scopes>
```

| Scope | Allowed write areas |
|---|---|
| `recipe_import` | Recipe creation/PATCH, images, assets, duplicate, last-made, ZIP/image/URL imports |
| `shopping` | Shopping lists, items, bulk operations, recipe ingredients added to lists |
| `mealplan` | Meal-plan entries, random suggestions, and meal-plan rules |
| `parser` | Generic parser API mutations; the dedicated non-persisting ingredient parser does not require mutation mode |
| `organizers` | Categories, tags, foods, and units |
| `cookbooks` | Household cookbooks |
| `comments` | Recipe comments |
| `timeline` | Recipe timeline events and images |
| `recipe_actions` | Household recipe actions |
| `all` | Every non-sensitive mutation; use only for tightly trusted clients |

Example for recipe imports and organizer cleanup:

```text
MEALIE_MCP_ALLOW_MUTATIONS=true
MEALIE_MCP_MUTATION_SCOPE=recipe_import,organizers
```

Scopes do not override the sensitive-endpoint denylist or confirmation requirements.
URL imports additionally require `MEALIE_MCP_ALLOW_URL_IMPORTS=true`. Remote image or asset sources additionally require `MEALIE_MCP_ALLOW_REMOTE_SOURCES=true`.

## Main capabilities

The server currently registers 38 MCP tools, including:

- recipe search, lookup, suggestions, URL/text imports, duplication, last-made updates;
- image replacement, source asset upload, cover cropping, and cookbook-image OCR;
- shopping-list and meal-plan CRUD helpers using Mealie v3 full-model updates;
- organizer listing and ingredient parsing;
- Chefkoch search and recipe extraction;
- live OpenAPI catalog search;
- generic JSON/multipart requests and controlled binary downloads for non-sensitive operations.

Use `mealie_api_operations` before a generic OpenAPI call. It validates operation IDs, path/query parameters, required body fields, content type, sensitivity, confirmation, and mutation scope.

## File and download configuration

| Variable | Default | Purpose |
|---|---|---|
| `MEALIE_MCP_DATA_DIR` | `~/.cache/mealie-mcp` | Runtime data root |
| `MEALIE_MCP_DOWNLOAD_DIR` | `$DATA_DIR/downloads` | Controlled download directory |
| `MEALIE_MCP_ALLOWED_LOCAL_ROOTS` | empty | Additional local upload roots, separated by the OS path separator |
| `MEALIE_MCP_MAX_DOWNLOAD_BYTES` | 100 MiB | Maximum binary download size |
| `MEALIE_MCP_MAX_JSON_BYTES` | 10 MiB | Maximum JSON response size |
| `MEALIE_MCP_MAX_OPENAPI_BYTES` | 20 MiB | Maximum OpenAPI response size |
| `MEALIE_MCP_MAX_IMAGE_PIXELS` | 40,000,000 | Maximum decoded image pixels |
| `MEALIE_MCP_OCR_TIMEOUT` | 60 seconds | Tesseract timeout per OCR call |
| `MEALIE_MCP_TIMEOUT` | 30 seconds | HTTP timeout |
| `MEALIE_MCP_ALLOW_URL_IMPORTS` | `false` | Allow Mealie to fetch validated public recipe URLs |
| `MEALIE_MCP_ALLOW_REMOTE_SOURCES` | `false` | Allow this MCP process to fetch validated public file URLs |

Default local upload roots are `$DATA_DIR/imports` and the download directory. Add the narrowest possible absolute path when another client-managed media cache is needed.

## Development

```bash
uv sync --frozen --all-groups
uv run python -m compileall -q mealie_server.py tests
uv run ruff check mealie_server.py tests
uv run python -m unittest discover -s tests -p 'test_*.py' -v
uv run pip-audit --skip-editable
```

The regression suite mocks network and filesystem boundaries. It covers mutation gating, confirmation, sensitive-path blocking, OpenAPI validation, SSRF/local-file confinement, multipart limits, Mealie v3 request shapes, ingredient preservation, and credential-safe status output.

## Known boundaries

- This is a stdio MCP server, not a remotely exposed HTTP service.
- Mealie streaming/SSE import operations are intentionally unsupported.
- Generic operations follow the live Mealie OpenAPI, but dedicated helper tools may need adaptation after breaking Mealie API changes.
- Raw API paths are fail-closed unless they match a live OpenAPI operation; sensitive path prefixes and OpenAPI tags remain denied.
- Public-address validation reduces SSRF risk but cannot enforce the network behavior of Mealie itself. When enabling URL imports or remote sources, also restrict container/host egress and DNS at the deployment layer.
- Chefkoch integration is optional functionality supplied through the `get-chefkoch` dependency.
- OCR quality depends on the local Tesseract installation and source image quality.

## License

MIT — see [LICENSE](LICENSE).
