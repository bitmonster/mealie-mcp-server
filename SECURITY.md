# Security Policy

## Supported versions

Until a stable release exists, security fixes are applied to the latest `main` branch.

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's **Security → Report a vulnerability** feature. Do not open a public issue containing credentials, private URLs, exploit payloads, or user data.

Include:

- affected commit or version;
- reproduction steps;
- expected and observed behavior;
- impact assessment;
- suggested mitigation, if available.

## Deployment guidance

- Use a dedicated Mealie long-lived token with the least privilege available in your Mealie deployment.
- Keep `MEALIE_MCP_ALLOW_MUTATIONS=false` unless writes are required.
- Enable only the mutation scopes needed by the client. Avoid `all`.
- Keep URL imports and remote file sources disabled unless required. If enabled, enforce outbound DNS/network policy around both the MCP process and Mealie.
- Use HTTPS for every non-loopback `MEALIE_BASE_URL`; authenticated API redirects are intentionally rejected.
- Keep the server on stdio behind a trusted MCP client; do not expose its stdin/stdout transport directly to a network.
- Never fetch tokens directly from the Mealie database in a shared or published launcher.
- Restrict `MEALIE_MCP_ALLOWED_LOCAL_ROOTS` to dedicated import directories.
- Treat every `confirmed_by_user=true` value as an authorization claim made by the calling agent; configure the agent to obtain a real preview and explicit user confirmation first.

## Security invariants

The project treats these as release-blocking invariants:

1. mutations are disabled by default;
2. empty or unknown mutation scopes deny writes;
3. sensitive OpenAPI paths and tags remain blocked regardless of scope;
4. every persisting helper and generic mutation requires explicit confirmation;
5. remote fetch features are disabled by default and cannot resolve to non-public networks when enabled;
6. local sources cannot escape configured roots through traversal or symlinks;
7. credentials are not returned by status tools or exception text;
8. raw API paths must match the live OpenAPI and pass both path- and tag-based sensitivity checks;
9. response sizes, image pixels, pagination, and OCR duration are bounded.
