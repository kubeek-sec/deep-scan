# YARA rules - attribution

These YARA rules are vendored from the **Cisco AI Defense `mcp-scanner`** project
and are licensed under the **Apache License 2.0**.

- Upstream: https://github.com/cisco-ai-defense/mcp-scanner
- Author: Cisco (see each rule's `meta.author`)
- License: Apache-2.0 (see the upstream `LICENSE`)

They are used unmodified by Deep Scan's `yara` scanner to flag malicious intent
(prompt injection, tool poisoning, command/SQL/script/code injection, credential
harvesting, data exfiltration, system manipulation) in source code and in
tool/skill descriptions. Per the Apache-2.0 terms, this notice preserves the
upstream attribution; no endorsement by Cisco is implied.
