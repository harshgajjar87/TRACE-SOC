import sys
from pathlib import Path

# Add project root to sys.path so 'normalizer', 'database', etc. are importable
sys.path.insert(0, str(Path(__file__).parent))
