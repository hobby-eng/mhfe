#!/bin/sh
# Starts mhfe from this folder with its menu: choose a command with the arrow keys and Enter. When
# a browser tool and its checksum file mhfe-fast-mode.sha256 lie here too, the first entry serves
# that tool in fast mode. Commands with options are typed, such as ./mhfe encrypt --pim 1.
cd "$(dirname "$0")" && exec ./mhfe
