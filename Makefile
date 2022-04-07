all: fmt build test

build:
	go build -o ./jarscanner ./cmd/jarscanner/

debug:
	dlv debug --headless --listen=:2345 --api-version=2 --accept-multiclient ./cmd/jarscanner/ -- -config jarscanner.yml

run:
	./jarscannert -debug -ok ./test

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
