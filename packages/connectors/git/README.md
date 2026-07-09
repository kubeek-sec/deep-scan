# deepscan-input-connector-git

Scan a repository by **direct git URL** - no organization or group to
enumerate, and **no token required** for public repos.

## Scope config

```json
{ "url": "https://github.com/michoo/flanby" }
```

or several, optionally authenticated and/or branch-pinned:

```json
{
  "urls": ["https://github.com/acme/api", "https://gitlab.com/acme/infra"],
  "branch": "main",
  "token_env": "GITHUB_TOKEN",
  "auth_username": "x-access-token"
}
```

- Omit `token_env` (or leave the variable empty) to clone **anonymously** -
  ideal for a single public repo.
- `token_env` names an **environment variable** holding a PAT; it is read at run
  time and never written to the database. Provision it via `.env` (docker
  compose) or a Kubernetes secret (see `deploy/`).
- `auth_username` defaults to `x-access-token` (GitHub). Use `oauth2` for GitLab
  PATs.
- `branch` is optional; without it the remote's default branch (HEAD) is used.

Change detection is `git ls-remote` (one round trip, no clone); materializing is
a shallow single-branch clone. Works against any http(s) git host.

```bash
deepscan-kruncher scope add flanby git \
    --config '{"url":"https://github.com/michoo/flanby"}'
```
