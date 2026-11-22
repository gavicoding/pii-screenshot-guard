"""Module execution entrypoint (`python -m pii_guard`)."""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
