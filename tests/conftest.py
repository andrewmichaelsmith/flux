"""Put the repo root on sys.path so `import flux.server` works without
installing the package first. Keeps `python -m pytest` friction-free."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
