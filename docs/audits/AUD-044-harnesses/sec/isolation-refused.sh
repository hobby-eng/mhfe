#!/usr/bin/env bash
# AUD-044 SEC: what mhfe says on a kernel that refuses seccomp and Landlock (refuse-isolation.so), by
# command: the summary of a command with settings, the commands without one, and self-test.
#   isolation-refused.sh <path to mhfe> <path to refuse-isolation.so>
set -uo pipefail
mhfe="$1"; shim="$2"
filter() { grep -E 'Isolation|isolation|network|Password|words|Core dumps|Locked' | cut -c1-110; }
echo "=== encrypt --stdin, stopped at its first answer"
LD_PRELOAD="$shim" "$mhfe" encrypt --stdin < /dev/null 2>&1 | filter
echo "=== password --words 5 (the password itself replaced)"
LD_PRELOAD="$shim" "$mhfe" password --words 5 < /dev/null 2>&1 | sed -E '/^[a-z]+( [a-z]+){4}$/s/.*/<the password>/'
echo "=== repair-words, stopped at its first answer"
LD_PRELOAD="$shim" "$mhfe" repair-words --count 2 < /dev/null 2>&1 | cut -c1-110
echo "=== self-test"
LD_PRELOAD="$shim" "$mhfe" self-test < /dev/null 2>&1 | grep -iE 'isolation|core dumps|file|passed|warning|!' | cut -c1-110
