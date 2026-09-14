# Mirrors WAF Backend Makefile
GO ?= go

BIN_DIR := bin
BIN := $(BIN_DIR)/server

# The admin UI is embedded via go:embed, so the backend cannot compile
# without these assets. The stamp rule below builds them on demand; touch
# admin-ui sources and run `make admin-ui-build` to refresh the embed.
ADMINUI_DIST := internal/adminui/dist/index.html

VERSION ?= dev
COMMIT ?= none
BUILD_TIME ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w \
	-X github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/version.Version=$(VERSION) \
	-X github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/version.Commit=$(COMMIT) \
	-X github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/version.BuildTime=$(BUILD_TIME)

.PHONY: all build run test test-race test-postgres coverage vet lint fmt tidy admin-ui-install admin-ui-check admin-ui-build build-all migrate-up migrate-down clean help

all: build

build: $(ADMINUI_DIST)
	@echo ">> Building $(BIN)"
	@mkdir -p $(BIN_DIR)
	@$(GO) build -ldflags '$(LDFLAGS)' -o $(BIN) ./cmd/server

$(ADMINUI_DIST):
	@npm --prefix admin-ui install
	@npm --prefix admin-ui run build

run: $(ADMINUI_DIST)
	@$(GO) run -ldflags '$(LDFLAGS)' ./cmd/server

test:
	@$(GO) test -count=1 ./...

test-race:
	@$(GO) test -race -count=1 ./...

test-postgres:
	@test -n "$(POSTGRES_TEST_DSN)" || (echo "POSTGRES_TEST_DSN is required, e.g. postgres://user:pass@127.0.0.1:5432/db?sslmode=disable" && exit 1)
	@POSTGRES_TEST_DSN="$(POSTGRES_TEST_DSN)" $(GO) test -tags=integration -count=1 -v ./internal/storage/postgres

coverage:
	@packages=`$(GO) list -f '{{if or .TestGoFiles .XTestGoFiles}}{{.ImportPath}}{{end}}' ./...`; \
	if test -z "$$packages"; then echo "no test packages found"; exit 1; fi; \
	$(GO) test -count=1 -coverpkg=./... -coverprofile=coverage.out $$packages
	@$(GO) tool cover -func=coverage.out

vet:
	@$(GO) vet ./...

lint:
	@echo ">> Running golangci-lint"
	@golangci-lint run ./... || (echo "[warn] golangci-lint not installed; running go vet instead" && $(GO) vet ./...)

fmt:
	@$(GO) fmt ./...

tidy:
	@$(GO) mod tidy

admin-ui-install:
	@npm --prefix admin-ui install

admin-ui-check:
	@npm --prefix admin-ui run check

admin-ui-build:
	@npm --prefix admin-ui install
	@npm --prefix admin-ui run build

build-all: admin-ui-build build

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
	@echo "  test-postgres - Run PostgreSQL integration tests (requires POSTGRES_TEST_DSN)"
	@echo "  coverage      - Generate coverage.out and print coverage summary"
	@echo "  lint          - Run golangci-lint (fallback to go vet)"
	@echo "  fmt           - Format Go sources"
	@echo "  tidy          - go mod tidy"
	@echo "  admin-ui-install - Install admin UI dependencies"
	@echo "  admin-ui-check   - Type-check the admin UI"
	@echo "  admin-ui-build   - Build embedded admin UI assets"
	@echo "  build-all        - Build admin UI and backend"
	@echo "  migrate-up   - Apply DB migrations"
	@echo "  migrate-down - Roll back last DB migration"
	@echo "  clean        - Remove build artifacts"
