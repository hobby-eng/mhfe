#!/bin/sh
# macOS: double-click to start the fast mode for the browser tool in this folder. mhfe reads
# mhfe-fast-mode.sha256 next to it, checks the HTML file named there and serves it locally.
cd "$(dirname "$0")" && exec ./mhfe
