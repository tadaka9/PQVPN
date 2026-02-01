import sys
import os

# Ensure repository root (one level above tests/) is on sys.path so tests can import top-level modules
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
