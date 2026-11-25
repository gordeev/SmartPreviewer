#!/bin/bash
# Double-click on macOS: starts the SmartPreview connector (and PhotoCraft, if it is not running).
cd "$(dirname "$0")/connector" || exit 1
if ! command -v python3 >/dev/null 2>&1; then
  echo "Python 3 is required: https://www.python.org/downloads/"
  read -r -p "Press Return to close."
  exit 1
fi
exec python3 smartpreview.py "$@"
