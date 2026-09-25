"""Make the project root importable however the tests are launched."""

import os
import sys
from pathlib import Path

# Keep tests hermetic: ignore incident_platform/.env and never enable a real LLM,
# whatever is set in the developer's shell. Must run before `config` is imported.
os.environ["INCIDENT_PLATFORM_LOAD_DOTENV"] = "false"
os.environ["INCIDENT_PLATFORM_USE_REAL_LLM"] = "false"

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
