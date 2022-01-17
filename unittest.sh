#!/bin/bash
set -ex

TMPFILE=$(mktemp)

./log4shelldetect -l4jversion -hash test/ > "$TMPFILE"

COUNT=$(cat "${TMPFILE}" | wc -l)
test "$COUNT" -eq 58

UNKNOWNS_COUNT=$(grep -cE '(NOFILE|EMPTY|NOZIP)' "$TMPFILE")
test "${UNKNOWNS_COUNT}" -eq 4

L4J2_COUNT=$(awk '$2~/^2\./{a+=1}END{print a}' "$TMPFILE")
test "${L4J2_COUNT}" -eq 54

WORKAROUND_COUNT=$(grep -c WORKAROUND "$TMPFILE")
test "${WORKAROUND_COUNT}" -eq 11

echo OK
