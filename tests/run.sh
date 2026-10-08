#!/bin/bash
# Run the whole suite (bash 3.2 + system python3 only, no network, no real notifications).
cd "$(dirname "$0")/.." && exec /usr/bin/python3 -I -m unittest discover -s tests -p 'test_*.py' "$@"
