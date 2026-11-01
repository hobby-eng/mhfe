#!/usr/bin/env bash
# AUD-044 fun probe: truncated and damaged input in script mode, on the reduced-cost command line.
set -u
R=../tmp/aud044/fun/mhfe-reduced
C="$(cat ../tmp/aud044/fun/c12.txt)"
PW="public test password"
last() { tail -${1:-2} | cut -c1-130; }
run() { local label="$1"; shift; printf '== %s\n' "$label"; "$@" 2>&1 | grep -v '^$\|Note:\|Isolation\|Secrets\|Settings\|More:' | last 3; echo "exit ${PIPESTATUS[0]}"; }
p() { printf "$@"; }
# word count
W=($C)
run "23 words" bash -c "printf '%s\n%s\n' \"${W[*]:0:23}\" \"$PW\" | $R decrypt --stdin"
run "25 words" bash -c "printf '%s\n%s\n' \"$C abandon\" \"$PW\" | $R decrypt --stdin"
run "empty container line" bash -c "printf '\n%s\n' \"$PW\" | $R decrypt --stdin"
run "no input at all" bash -c "$R decrypt --stdin < /dev/null"
run "container, no password line" bash -c "printf '%s\n' \"$C\" | $R decrypt --stdin"
run "password line empty" bash -c "printf '%s\n\n' \"$C\" | $R decrypt --stdin"
run "bad checksum (last word)" bash -c "printf '%s\n%s\n' \"${W[*]:0:23} abandon\" \"$PW\" | $R decrypt --stdin"
run "unknown word 5" bash -c "printf '%s\n%s\n' \"${W[*]:0:4} zzzz ${W[*]:5}\" \"$PW\" | $R decrypt --stdin"
run "? in container, script" bash -c "printf '%s\n%s\n' \"? ${W[*]:1}\" \"$PW\" | $R decrypt --stdin"
run "four-letter words, capitals, tabs" bash -c "printf '%s\n%s\n' \"$(echo $C | sed -E 's/([a-z]{4})[a-z]*/\U\1/g; s/ /\t  /g')\" \"$PW\" | $R decrypt --stdin"
run "NUL in container line" bash -c "printf '%s\0x\n%s\n' \"$C\" \"$PW\" | $R decrypt --stdin"
run "invalid UTF-8 in password" bash -c "printf '%s\n\xff\xfe\n' \"$C\" | $R decrypt --stdin"
run "BOM before container" bash -c "printf '\xef\xbb\xbf%s\n%s\n' \"$C\" \"$PW\" | $R decrypt --stdin"
run "CRLF lines" bash -c "printf '%s\r\n%s\r\n' \"$C\" \"$PW\" | $R decrypt --stdin"
run "CR inside password" bash -c "printf '%s\npublic\rtest\n' \"$C\" | $R decrypt --stdin"
run "TAB in password" bash -c "printf '%s\npublic\ttest\n' \"$C\" | $R decrypt --stdin"
L=$(python3 -I -c "print('a'*1024)"); M=$(python3 -I -c "print('a'*1025)")
run "password 1024 bytes" bash -c "printf '%s\n%s\n' \"$C\" \"$L\" | $R decrypt --stdin"
run "password 1025 bytes" bash -c "printf '%s\n%s\n' \"$C\" \"$M\" | $R decrypt --stdin"
BIG=$(python3 -I -c "print('a'*100000)")
printf '%s\n%s\n' "$C" "$BIG" > big.in
run "password 100,000 bytes" bash -c "$R decrypt --stdin < big.in"
