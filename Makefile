all: fmt build test

build:
	go build -o ./log4shelldetect ./

debug:
	dlv debug --headless --listen=:2345 --api-version=2 --accept-multiclient ./ -- -debug -ok -class log4j/core/lookup/JndiLookup.class -pom META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties -exclude '.*test/excluded/.*' ./test/ex*

run:
	./log4shelldetect -debug -ok ./test

fmt:
	gofmt -w .

test: unittest sec lint

sec:
	gosec ./...

lint:
	golangci-lint run

unittest:
	./unittest.sh
	find . -name '*_test.go' | while read f; do dirname $$f; done | sort -u | while read d; do go test $$d; done
