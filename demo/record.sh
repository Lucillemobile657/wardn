#!/bin/bash
# wardn demo recorder
# Usage: ./demo/record.sh
set -e

CAST_FILE="demo/wardn-demo.cast"
DEMO_SCRIPT="demo/demo.sh"

echo "Recording wardn demo..."
echo "This will run the demo script inside asciinema."
echo ""

asciinema rec "$CAST_FILE" \
  --title "wardn — credential isolation for AI agents" \
  --cols 100 \
  --rows 30 \
  --command "bash $DEMO_SCRIPT"

echo ""
echo "Recording saved to $CAST_FILE"
echo ""
echo "Upload with:"
echo "  asciinema upload $CAST_FILE"
echo ""
echo "Or embed in README with:"
echo "  [![asciicast](https://asciinema.org/a/XXXXX.svg)](https://asciinema.org/a/XXXXX)"
