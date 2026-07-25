# Mirrors WAF Backend Makefile
# Go binary override (Windows-friendly; default assumes Go on PATH)
GO ?= "C:/Users/Ran/sdk/go1.24.4/bin/go.exe"

# Allow overriding via shell PATH on non-Windows
ifneq ($(OS),Windows_NT)
	GO := go
endif

BIN_DIR := bin
BIN := $(BIN_DIR)/server

VERSION ?= dev
COMMIT ?= none
BUILD_TIME ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w \
	-X github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/version.Version=$(VERSION) \
	-X github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/version.Commit=$(COMMIT) \
	-X github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/version.BuildTime=$(BUILD_TIME)

.PHONY: all build run test test-race vet lint fmt tidy migrate-up migrate-down clean help

all: build

build:
	@echo ">> Building $(BIN)"
	@mkdir -p $(BIN_DIR)
	@$(GO) build -ldflags '$(LDFLAGS)' -o $(BIN) ./cmd/server

run:
	@$(GO) run -ldflags '$(LDFLAGS)' ./cmd/server

test:
	@$(GO) test -count=1 ./...

test-race:
	@$(GO) test -race -count=1 ./...

vet:
	@$(GO) vet ./...

lint:
	@echo ">> Running golangci-lint"
	@golangci-lint run ./... || (echo "[warn] golangci-lint not installed; running go vet instead" && $(GO) vet ./...)

fmt:
	@$(GO) fmt ./...

tidy:
	@$(GO) mod tidy

migrate-up:
	@$(GO) run github.com/pressly/goose/v3/cmd/goose -dir migrations up

migrate-down:
	@$(GO) run github.com/pressly/goose/v3/cmd/goose -dir migrations down

clean:
	@rm -rf $(BIN_DIR)

help:
	@echo "Targets:"
	@echo "  build        - Compile backend into $(BIN)"
	@echo "  run          - Run backend from source"
	@echo "  test         - Run unit tests"
	@echo "  test-race    - Run unit tests with race detector"
	@echo "  vet          - Run go vet"
	@echo "  lint         - Run golangci-lint (fallback to go vet)"
	@echo "  fmt          - Format Go sources"
	@echo "  tidy         - go mod tidy"
	@echo "  migrate-up   - Apply DB migrations"
	@echo "  migrate-down - Roll back last DB migration"
	@echo "  clean        - Remove build artifacts"
