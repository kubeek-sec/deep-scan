"""Test session setup.

Disable telemetry for the whole suite so tests never emit Sentry events even
when a real ``SENTRY_DSN`` is present in the project ``.env`` (os.environ wins
over the dotenv fallback in ``config.get``).
"""

import os

os.environ["DEEPSCAN_TELEMETRY"] = "false"
