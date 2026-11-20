# ADR 0008: Expiring, revocable session tokens

[Project overview](../../README.md) · [ADR index](README.md)

| | |
| :--- | :--- |
| Decision status | Accepted (2026-11-20, repository owner) |
| Implementation status | Implemented (2026-11-20) |
| Related | [ADR 0001](0001-ai-access-through-mcp-and-access-tokens.md) |

## Context

After the OIDC login, DTVP keeps the user signed in with its own session
cookie: an HS256 JWT signed with `DTVP_SESSION_SECRET_KEY`. Until this
decision:

- The token held only the user (`{"sub": ...}`). It never expired, and
  nothing on the server could end it. Logout only deleted the cookie in the
  browser; a copied cookie stayed valid for good.
- The key defaulted to `change_me`, and Compose fell back to it. Anyone who
  knew the default could sign a cookie for any user of a deployment that kept
  it.
- The same key signs the OIDC login-state cookie and SSVC evidence tokens,
  which DTVP hands to the browser. Any validly signed JWT was accepted as a
  session, so an evidence token authenticated as a user without a name.

Access tokens for machine clients already expire and can be revoked
([ADR 0001](0001-ai-access-through-mcp-and-access-tokens.md)); browser
sessions could not.

## Drivers

- A leaked or copied session cookie must stop working: after a bounded time,
  on logout, and when a reviewer revokes it.
- A deployment must not run with a guessable signing key, including through a
  forgotten Compose default.
- Users who work all day should not be signed out while they work.
- Correct with more than one backend worker and across restarts.
- No new infrastructure, and no new database or migration namespace.

## Decision

1. **The signing key is checked before DTVP serves.** It must be set
   (`DTVP_SESSION_SECRET_KEY`, or a file named by
   `DTVP_SESSION_SECRET_KEY_FILE`), must not be `change_me`, and must have at
   least 32 bytes. The boot wrapper checks it on lifespan startup and reports
   `lifespan.startup.failed`, so uvicorn exits; `dtvp.auth` checks it again at
   import for deployments that serve `dtvp.main:app` directly. Keys
   committed to the repository for the local stack, VS Code and the tests
   start with `dtvp-dev-only-` and are accepted only with
   `DTVP_SESSION_ALLOW_DEV_KEY=true`; copied into a deployment without that
   flag, they are refused like `change_me`.
2. **Session tokens are typed and expire.** The claims are `typ`
   (`dtvp-session`), `sub`, `ver`, `iat`, `exp`, and `auth_time` (the
   sign-in), signed with HS256. A token without all of them, of another type,
   or expired is rejected. The lifetime is `DTVP_SESSION_TTL_HOURS` (default
   12, 1–720).
3. **Sliding renewal, with an absolute cap.** A request with a token past
   half its lifetime gets a new cookie with a fresh `iat` and `exp`, the same
   version and the same `auth_time`. An HTTP middleware sets it on whatever
   response the route produced. No token reaches past `auth_time` plus
   `DTVP_SESSION_MAX_AGE_HOURS` (default 168, one week; at least the
   lifetime): after that the user signs in again, however active.
4. **A per-user session version is stored server-side** in the
   `session_versions` table of the `access_tokens` migration namespace
   (migration `0002`), in the access-token database. Every authenticated
   browser request reads it; a token whose `ver` differs is rejected. A
   failed read is a `503`, not a `401`, so the SPA does not loop to sign-in;
   so is a failed read at sign-in.
5. **Logout and revocation raise the version.** `GET /auth/logout` ends all
   sessions of the signed-in user (unless the presented session is already
   revoked). `POST /auth/sessions/revoke` with `{"username": ...}` ends all
   sessions of a user; users may revoke their own, reviewers anyone's. Only
   interactive sessions may call it, not access tokens. When the version
   cannot be written, both answer `503` and keep the cookie: a sign-out that
   only deleted the cookie would leave every copy of the session valid.

## Alternatives

- **Server-side session table with opaque session IDs.** Allows ending one
  device rather than all and listing sessions, but needs a write per sign-in
  and a cleanup job, and replaces the signed token entirely. More than the
  threat requires for now.
- **Short lifetime without revocation.** No database read per request, but a
  stolen cookie stays valid until it expires and logout still ends nothing on
  the server.
- **A key derived per purpose** (session, login state, SSVC evidence). The
  typed claims already keep evidence tokens from passing as sessions; separate
  keys would also contain a leak of one purpose. Left for a later change.

## Consequences

- One small indexed read per authenticated browser request.
- Cookies issued before this change carry no expiry and are rejected: every
  user signs in once after the upgrade.
- Logout ends the user's sessions on every device, not only the current one.
- A session in continuous use ends at the absolute maximum age; the user
  signs in again once a week by default.
- Logout stays a `GET` because the SPA navigates to it. A cross-site link can
  therefore sign a user out (a nuisance, not a takeover); `SameSite=Lax`
  cookies are sent on such top-level navigations.
- Rotating the signing key signs everyone out and invalidates SSVC
  suggestions that are open in a browser.
- Deployments must provide a strong key; the container exits otherwise.

## Confirmation

- `tests/test_session_services.py`: key and key-file checks, lifetime
  parsing, token claims, rejection of expired, legacy, untyped, wrongly
  signed, and SSVC evidence tokens, and the renewal threshold.
- `tests/test_boot.py`: startup fails without a strong key and the
  application is not loaded.
- `tests/test_access_tokens.py`: session versions, their persistence, and
  migration `0002` on a database that has only `0001`.
- `tests/test_auth.py`: the issued cookie, rejection of legacy, expired, and
  evidence cookies, logout of all sessions, reviewer and self revocation,
  renewal on `/auth` and `/api` routes, and `503` when the version cannot be
  read or written (requests, sign-in, sign-out, revocation). The absolute
  maximum age is in `tests/test_session_services.py`.
- `tests/test_session_config_files.py`: Compose has no placeholder fallback;
  the pm2 stack, the documented development exports, VS Code and the test
  suite carry development keys that are refused without the development
  flag.
