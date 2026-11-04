"""python -m minimalcult verify <file.json> [--key HEX] [--pq-key HEX] [--json]"""
import sys

from .verify import main

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
