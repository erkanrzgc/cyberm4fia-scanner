# cyberm4fia-scanner — common dev tasks
#
# Usage:
#   make help              # list available targets
#   make test              # default unit suite (fast)
#   make integration-up    # bring up docker-compose fixtures
#   make integration       # run the marked integration tests
#   make integration-down  # tear them down

.PHONY: help test test-cov integration integration-up integration-down \
        integration-tls integration-clean

help:
	@grep -E '^[a-zA-Z][a-zA-Z0-9_-]+:.*?##' $(MAKEFILE_LIST) | awk \
	  'BEGIN {FS = ":.*?## "}; {printf "  %-22s %s\n", $$1, $$2}'

test: ## Run the default unit suite (fast, no Docker)
	python3 -m pytest -q

test-cov: ## Unit suite with coverage report
	python3 -m pytest --cov=. --cov-report=term-missing

integration-tls: ## Generate the throwaway TLS cert for the weak-tls fixture
	mkdir -p tests/integration/fixtures/tls
	@if [ ! -f tests/integration/fixtures/tls/cert.pem ]; then \
	  openssl req -x509 -nodes -newkey rsa:2048 \
	    -keyout tests/integration/fixtures/tls/key.pem \
	    -out tests/integration/fixtures/tls/cert.pem \
	    -days 3650 -subj "/CN=weak-tls-fixture.test"; \
	fi

integration-up: integration-tls ## Bring up docker-compose integration fixtures
	docker compose -f docker-compose.integration.yml up -d
	@echo "fixtures up. give services ~10s to settle before running 'make integration'."

integration: ## Run the integration test suite (skips when prereqs are missing)
	python3 -m pytest -m integration tests/integration/ -v

integration-down: ## Tear down the integration fixture services
	docker compose -f docker-compose.integration.yml down -v

integration-clean: integration-down ## Tear down + remove generated TLS cert
	rm -f tests/integration/fixtures/tls/cert.pem tests/integration/fixtures/tls/key.pem
