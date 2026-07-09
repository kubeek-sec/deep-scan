# deepscan-input-connector-gitlab

Discovers projects under a GitLab **group** (subgroups included) or **user**
and exposes each as a git source. Works against gitlab.com and self-managed
instances (`base_url`).

## Scope config

```json
{
  "group": "my-group/platform",
  "base_url": "https://gitlab.com",
  "token_env": "GITLAB_TOKEN",
  "include_subgroups": true,
  "include_archived": false,
  "name_regex": "^infra-"
}
```

Use `"user": "some-user"` instead of `"group"` for a user namespace. The token
(read from `token_env`) needs `read_api` + `read_repository` scope.

- **Discovery** pages the projects API via the `X-Next-Page` header.
- **Change detection** is `git ls-remote` on the default branch.
- **Cloning** is a shallow single-branch clone with `oauth2:<token>` basic auth.

Register via `deepscan-kruncher scope add platform gitlab --config '{"group":"my-group/platform","token_env":"GITLAB_TOKEN"}'`.
