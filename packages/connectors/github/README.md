# deepscan-input-connector-github

Discovers repositories under a GitHub **organization** or **user** and exposes
each as a git source for the kruncher. Works against github.com and GitHub
Enterprise (`base_url`).

## Scope config

```json
{
  "org": "my-org",
  "base_url": "https://api.github.com",
  "token_env": "GITHUB_TOKEN",
  "include_archived": false,
  "include_forks": false,
  "name_regex": "^team-"
}
```

Use `"user": "octocat"` instead of `"org"` for a user account. The token is
read from the named environment variable (never stored in the DB) and is
required for private repos and to lift the unauthenticated rate limit. It needs
`repo:read` / `contents:read` scope.

- **Discovery** pages through the repos API (`per_page=100`, `Link` header).
- **Change detection** is `git ls-remote` on the repo's default branch - one
  round trip, no clone.
- **Cloning** is a shallow single-branch clone with `x-access-token:<token>`
  basic auth.

Register via `deepscan-kruncher scope add my-org github --config '{"org":"my-org","token_env":"GITHUB_TOKEN"}'`.
