.PHONY: all build build-web test test-race test-postgres test-web tidy-check lint smoke ci run clean docker-build

all: build

build-web:
	@echo "==> Building frontend web assets..."
	@cd web && npm ci && npm run build

build: build-web
	@echo "==> Compiling kymessages binary..."
	@go build -o kymessages ./cmd/server

test: build-web
	@echo "==> Running test suite..."
	@go test -v ./...

# The full API integration package can exceed Go's 10-minute default under race/coverage.
test-race: build-web
	@echo "==> Running test suite with race detector..."
	@go test -race -timeout=30m -covermode=atomic -coverprofile=coverage.out ./...
	@go tool cover -func=coverage.out | tail -1

# Runs the same suite against PostgreSQL; needs a reachable server.
test-postgres: build-web
	@echo "==> Running test suite against PostgreSQL..."
	@KY_TEST_POSTGRES_DSN="$${KY_TEST_POSTGRES_DSN:-postgres://postgres:postgrespassword@127.0.0.1:5432/ky_server?sslmode=disable}" go test -timeout=30m -count=1 ./...

test-web:
	@echo "==> Running frontend test suite..."
	@cd web && npm ci && npm test

# The same gate CI runs: a stale go.sum fails the build there, so fail here first.
tidy-check:
	@echo "==> Checking go.mod is tidy..."
	@go mod tidy
	@git diff --exit-code go.mod go.sum

lint:
	@echo "==> Checking formatting and vet..."
	@test -z "$$(gofmt -l $$(git ls-files '*.go'))" || { echo "gofmt needed:"; gofmt -l $$(git ls-files '*.go'); exit 1; }
	@go vet ./...
	@bash scripts/check-compose-proxy.sh
	@bash scripts/check-build-tags.sh
	@bash scripts/check-pqc-tls.sh

smoke: build
	@./scripts/smoke-test.sh

ci: tidy-check lint test-race test-web smoke
	@echo "==> Local CI checks passed"

run: build
	@./kymessages

docker-build:
	@docker build -t kymessages .

clean:
	@rm -rf kymessages web/dist web/node_modules coverage.out web/src/pqc/pqc.wasm web/src/crypto/pkg/kycrypto_bg.wasm
