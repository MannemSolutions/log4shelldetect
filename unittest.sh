#!/bin/bash
set -ex

TMPFILE=$(mktemp)
ln -sf DOESNTEXIST.jar test/broken/brokenlink.jar

./log4shelldetect -modversion -hash -class org/springframework/beans -class log4j/core/lookup/JndiLookup.class -pom META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties -class springframework/cloud/function/core -pom org.springframework.cloud/spring-cloud-function-core/pom.properties -exclude 'excluded' $PWD/test/ > "$TMPFILE"

COUNT=$(cat "${TMPFILE}" | wc -l)
test "$COUNT" -eq 61

UNKNOWNS_COUNT=$(grep -cE '(NOFILE|EMPTY|NOZIP)' "$TMPFILE")
test "${UNKNOWNS_COUNT}" -eq 4

L4J2_COUNT=$(awk '$2~/^2\./{a+=1}END{print a}' "$TMPFILE")
test "${L4J2_COUNT}" -eq 54

WORKAROUND_COUNT=$(grep -c WORKAROUND "$TMPFILE")
test "${WORKAROUND_COUNT}" -eq 11

echo OK
