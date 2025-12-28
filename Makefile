export GO111MODULE = on

.PHONY: test test-all test-cover lint

test:
	go test -short ./...

test-all:
	go test -race -cover ./...

test-cover:
	go test -race -coverprofile=test.out ./... && go tool cover --html=test.out

lint:
	golangci-lint run --timeout=600s && go vet ./...
