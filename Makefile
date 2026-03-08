.PHONY: build test lint docker push clean

BINARY    := airlock
REGISTRY  ?= ghcr.io/realugbun
IMAGE     := $(REGISTRY)/airlock
TAG       ?= latest
VERSION   ?= dev
COMMIT    := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS   := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X 'main.buildTime=$(BUILD_TIME)'

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o bin/$(BINARY) ./cmd/airlock

test:
	go test ./... -v -race -cover

lint:
	golangci-lint run ./...

docker:
	docker build --platform linux/amd64 --build-arg VERSION=$(VERSION) -t $(IMAGE):$(TAG) .

push: docker
	docker push $(IMAGE):$(TAG)

test-coverage:
	go test ./... -coverprofile=coverage.out
	go tool cover -html=coverage.out -o coverage.html

clean:
	rm -rf bin/ coverage.out coverage.html
