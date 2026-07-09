# deepscan-input-connector-directory

Wraps a directory the server can already read - **any contents, not only git**
checkouts (an NFS mount, an unpacked artifact, a shared volume) - so it can be
scanned on the same cadence as a repo.

## Scope config

```json
{
  "base_path": "/data/projects",
  "layout": "subdirs",
  "include_hidden": false,
  "name_regex": "^svc-",
  "snapshot": false
}
```

- `layout: "subdirs"` (default) - each immediate child directory is one source.
- `layout: "single"` - `base_path` itself is a single source.
- `snapshot: false` (default) - scan in place, read-only (cheapest). Set `true`
  to copy into a scratch dir first for a consistent view of a changing tree.

**Change detection** is a content-free signature over `(path, size, mtime)`:
no file is opened, so re-checks are cheap and any add/remove/edit/touch flips
the signature.

Register via `deepscan-kruncher scope add local-repos directory --config '{"base_path":"/data/projects"}'`.
