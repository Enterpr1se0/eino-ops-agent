.PHONY: dev-api dev-web build build-go build-web test test-web check clean

dev-api:
	go run ./cmd/ops-agent serve

dev-web:
	npm --prefix web run dev

build: build-web build-go

build-web:
	npm --prefix web install
	npm --prefix web run build

build-go:
	mkdir -p bin
	go build -buildvcs=false -trimpath -ldflags="-s -w" -o bin/ops-agent ./cmd/ops-agent

test:
	go test ./...

test-web:
	npm --prefix web run build

check: test test-web build-go

clean:
	rm -rf bin web/dist
