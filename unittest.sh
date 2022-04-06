#!/bin/bash
set -ex

TMPFILE=$(mktemp)
ln -sf DOESNTEXIST.jar test/broken/brokenlink.jar

./jarscanner -libversion -hash -exclude 'excluded' -config ./jarscanner.yml $PWD/test/ | sort > "$TMPFILE"

COUNT=$(cat "${TMPFILE}" | wc -l)
test "$COUNT" -eq 69

UNKNOWNS_COUNT=$(grep -cE '(NOFILE|EMPTY|NOZIP)' "$TMPFILE")
test "${UNKNOWNS_COUNT}" -eq 12

L4J2_COUNT=$(awk 'BEGIN{a=0;FS="|"}$3~/^ 2\./{a+=1}END{print a}' "$TMPFILE")
test "${L4J2_COUNT}" -eq 54

WORKAROUND_COUNT=$(grep -c WORKAROUND "$TMPFILE")
test "${WORKAROUND_COUNT}" -eq 11

echo OK
