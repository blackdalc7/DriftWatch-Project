# Driftwatch developer tasks. Run `make help`.
PY      ?= python3
VERSION ?= 1.0.0
LDFLAGS := -s -w -X main.Version=$(VERSION)
export PYTHONPATH := $(CURDIR)/src

.PHONY: help install lint test regress agent agent-test e2e pki secrets schema web web-test up down demo

help:          ## list targets
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-12s %s\n", $$1, $$2}'

install:       ## install Python dependencies into the current environment
	$(PY) -m pip install -r requirements.txt -r requirements-dev.txt ruff

lint:          ## ruff + gofmt/go vet
	$(PY) -m ruff check .
	cd agent && test -z "$$(gofmt -l .)" && go vet ./... && GOOS=windows go vet ./...

test:          ## Python tests with the 85% coverage gate
	$(PY) -m pytest --cov --cov-report=term-missing

regress:       ## offline detection regression gate over every rule and test
	$(PY) -m driftwatch regress --require-coverage

schema:        ## regenerate the test JSON Schema and the agent's catalog fixture
	$(PY) -m driftwatch schema --out schema/driftwatch-test.schema.json
	$(PY) -m driftwatch catalog > agent/internal/catalog/testdata/catalog.json

agent:         ## cross-compile the agent for the two lab VMs
	cd agent && CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/driftwatch-agent.exe ./cmd/driftwatch-agent
	cd agent && CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/driftwatch-agent ./cmd/driftwatch-agent
	cd agent/bin && sha256sum driftwatch-agent driftwatch-agent.exe > SHA256SUMS

agent-test:    ## Go unit tests
	cd agent && go test -race -cover ./...

e2e:           ## real server + mTLS proxy + Go agent on this host
	PYTHON=$(PY) scripts/e2e_local.sh

pki:           ## create deploy/pki (CA, server cert, bundle signing key)
	$(PY) -m driftwatch pki init --dir deploy/pki --hosts driftwatch.lab,localhost,127.0.0.1

secrets:       ## print random values for .env
	@$(PY) -c "import secrets; [print(f'{k}={secrets.token_urlsafe(32)}') for k in ('DRIFTWATCH_ADMIN_TOKEN','DRIFTWATCH_PROXY_SECRET','ELASTIC_PASSWORD','KIBANA_SYSTEM_PASSWORD','KIBANA_ENCRYPTION_KEY','MOCK_EDR_CLIENT_SECRET')]"

web:           ## build the UI into web/dist
	cd web && npm ci && npm run build

web-test:      ## UI type-check and unit tests
	cd web && npm run typecheck && npm test

demo:          ## seed data/driftwatch.sqlite3 with a synthetic week (no VMs needed)
	$(PY) -m driftwatch demo seed

up:            ## start the docker compose lab
	docker compose -f deploy/docker-compose.yml --env-file .env up -d --build

down:          ## stop the lab
	docker compose -f deploy/docker-compose.yml --env-file .env down
