#!/bin/bash
set -ex

TMPFILE=$(mktemp)

./log4shelldetect -modversion -hash -mod org/springframework/beans -mod log4j/core/lookup/JndiLookup.class -mod META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties -mod springframework/cloud/function/core -mod org.springframework.cloud/spring-cloud-function-core/pom.properties test/ > "$TMPFILE"

COUNT=$(cat "${TMPFILE}" | wc -l)
test "$COUNT" -eq 64

UNKNOWNS_COUNT=$(grep -cE '(NOFILE|EMPTY|NOZIP)' "$TMPFILE")
test "${UNKNOWNS_COUNT}" -eq 4

L4J2_COUNT=$(awk '$2~/^2\./{a+=1}END{print a}' "$TMPFILE")
test "${L4J2_COUNT}" -eq 54

WORKAROUND_COUNT=$(grep -c WORKAROUND "$TMPFILE")
test "${WORKAROUND_COUNT}" -eq 11

echo OK
