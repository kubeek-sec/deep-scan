"""AI triage support for the ``ai-analysis`` scanner.

Holds the headless Claude CLI invocation helper and the triage prompt. No model
is bundled - the scanner shells out to the ``claude`` CLI, which can be pointed
at a local, OpenAI/Anthropic-compatible model via ``ANTHROPIC_*`` env vars or a
settings file (see ``config.claude_*``).
"""
