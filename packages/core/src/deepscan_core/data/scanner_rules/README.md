# Scanner rules & config

Two layers feed each scanner's rules/config:

1. **Packaged defaults** - the rule sets that ship in this wheel, here under
   `data/scanner_rules/<scanner>/`. Only scanners that own their rules in-process
   ship defaults here:
   - `yara/` - the YARA rule files (`*.yara`) compiled by the `yara` scanner.
   - `mcp-threats/patterns.json` - the malicious-intent text patterns for `mcp-threats`.

2. **Operator overrides at runtime** - drop files in `<config>/<scanner-name>/`
   where `<config>` is `DEEPSCAN_CONFIG_DIR` (default `${DEEPSCAN_DATA_DIR}/config`,
   i.e. `/data/config` in the containers). A scanner uses its dir **only when it
   exists and is non-empty**; otherwise the tool's built-in / packaged defaults
   apply. Nothing changes until you add files - it is purely additive/opt-in.

The sub-directory name is the scanner's name (`scanner.name`). What each scanner
reads from `config/<name>/`:

| Scanner | `config/<name>/` content | How it's used |
|---|---|---|
| `yara` | `*.yara` | merged with packaged rules (same stem overrides) |
| `mcp-threats` | `patterns.json` | category overlay over the packaged patterns |
| `opengrep` | a rules dir (semgrep/opengrep `*.yaml`) | `--config <dir>` (replaces `auto`) |
| `gitleaks`, `betterleaks` | `*.toml` | `--config <file>` |
| `trufflehog` | `*.yaml` (custom detectors) | `--config <file>` |
| `nosey_parker` | rules dir | `--ruleset default --rules-path <dir>` |
| `kingfisher` | rules dir | `--rules-path <dir>` (in addition to builtins) |
| `titus` | rules file/dir | `--rules <dir>` |
| `checkov` | custom checks dir (+ optional `*.yaml`) | `--external-checks-dir <dir>` (+ `--config-file`) |
| `nuclei` | templates dir | `-t <dir>` (replaces the baked templates) |
| `trivy`, `trivy-misconfig`, `trivy-license` | `trivy.yaml` | `--config <file>` |
| `plumber` | `.plumber.yaml` (or `*.yaml`) | default policy when the target has none |

Example: to add a custom YARA rule without losing the built-ins, drop it at
`/data/config/yara/my_rule.yara`. To override gitleaks' ruleset, put a
`/data/config/gitleaks/gitleaks.toml`.
