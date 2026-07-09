# deepscan-input-connector-base

The contract every Deep Scan **input connector** implements, plus the registry
front-ends use to resolve connectors by name and a couple of shared helpers.

A connector turns a *scope* (an org, a group, a directory) into concrete,
scannable **sources** and separates the cheap part from the expensive part so
the scheduler can poll often and clone rarely:

```python
from deepscan_input_connector_base import get

c = get("github")
for src in c.discover({"org": "acme", "token_env": "GITHUB_TOKEN"}):
    rev = c.current_revision(src, cfg)     # cheap: ls-remote / dir signature
    path = c.materialize(src, rev, dest, cfg)  # expensive: clone / copy
```

## The contract

| Method | Purpose |
|---|---|
| `validate_config(config)` | Reject an unusable scope config early. |
| `discover(config)` | Yield `DiscoveredSource` for everything in the scope. |
| `current_revision(src, config)` | A cheap change token (git SHA, dir hash). |
| `materialize(src, rev, dest, config)` | Produce a local dir to scan. |

`DiscoveredSource` carries `external_id` (stable key), `kind` (`git`/`directory`),
`name`, `location` (clone URL or path), `default_branch` and `metadata`.

## Shared helpers

- `directory_signature(path)` - content-free `(path, size, mtime)` hash for
  change detection without reading any file.
- `git_support.ls_remote_sha` / `shallow_clone` - defensive git plumbing (no
  credential prompts, no system config, token injection without logging it).

Connectors register themselves at import (`register(MyConnector())`); the
kruncher imports the connector packages it ships with in `connectors.py`.
