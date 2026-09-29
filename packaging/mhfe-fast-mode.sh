#!/bin/sh
# Starts the fast mode for the browser tool in this folder: mhfe reads mhfe-fast-mode.sha256 next
# to it, checks the SHA-256 of the HTML file named there and serves it to this computer's browser.
cd "$(dirname "$0")" && exec ./mhfe
