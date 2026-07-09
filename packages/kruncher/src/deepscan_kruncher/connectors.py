"""Import the bundled connectors so they self-register, then re-export the
base registry. Importing this module is the single place that decides which
connectors a kruncher deployment ships with.
"""

from __future__ import annotations

from deepscan_input_connector_base import available, get  # noqa: F401

# Side-effecting imports: each module calls register() at import time.
import deepscan_input_connector_directory  # noqa: F401,E402
import deepscan_input_connector_git  # noqa: F401,E402
import deepscan_input_connector_github  # noqa: F401,E402
import deepscan_input_connector_gitlab  # noqa: F401,E402

__all__ = ["get", "available"]
