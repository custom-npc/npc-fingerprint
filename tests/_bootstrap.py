"""Import first in every test module: puts src/ on the path, shims rich if absent, isolates the data dir."""
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src"))
sys.path.insert(0, HERE)
import rich_shim  # noqa: E402,F401
os.environ.setdefault("NPC_FINGERPRINT_HOME", tempfile.mkdtemp(prefix="npcfp-test-"))
