APP_NAME := envoy-parse
VERSION := $(shell git describe --tags --always --dirty)
DOCKERHUB_UN ?= $(shell whoami)

# Supported architectures
LOCAL_ARCH := $(shell $(CURDIR)/scripts/functions/architecture.sh)
ARCHS := amd64 arm64

# ============> BACKEND Variables
BACKEND_DEV_IMAGE ?= $(DOCKERHUB_UN)/$(APP_NAME)-dev
BACKEND_APP_PORT ?= 8080 # Adapt this if the backend runs on another port
# Backend virtual environment directory
BACKEND_VENV := $(CURDIR)/.venv
PYTHON_BIN := $(BACKEND_VENV)/bin

##@ Linting
.PHONY: lint
lint: check-venv ## Run black, isort, and ruff Python code linters
	@$(PYTHON_BIN)/black .
	@$(PYTHON_BIN)/isort .
	@$(PYTHON_BIN)/ruff check .

.PHONY: check
check: check-venv ## Lint check formatting
	@$(PYTHON_BIN)/black --check .
	@$(PYTHON_BIN)/isort --check-only .
	@$(PYTHON_BIN)/ruff check .

.PHONY: check-venv
check-venv: ## Ensure the virtual environment and tools are set up
	@if [ ! -d "$(BACKEND_VENV)" ]; then \
		echo "Error: Virtual environment not found at $(BACKEND_VENV). Run 'make setup-venv' to create it."; \
		exit 1; \
	fi
	@if [ ! -x "$(PYTHON_BIN)/black" ] || [ ! -x "$(PYTHON_BIN)/isort" ] || [ ! -x "$(PYTHON_BIN)/ruff" ]; then \
		echo "Error: One or more linters are missing in the virtual environment. Run 'make setup-venv' to install them."; \
		exit 1; \
	fi

.PHONY: setup-venv
setup-venv: ## Create the virtual environment and install linters
	@if [ ! -d "$(BACKEND_VENV)" ]; then \
		python3 -m venv $(BACKEND_VENV); \
	fi
	@$(PYTHON_BIN)/pip install --upgrade pip
	@$(PYTHON_BIN)/pip install black isort ruff
	@echo "Virtual environment set up with linters."

##@ Tools
.PHONY: tools
tools: ## Installs various supporting Python development tools.
	@$(SHELL) $(CURDIR)/scripts/dev/devtools.sh

.PHONY: lint-tools
lint-tools: ## Install tools for linting
	@$(SHELL) $(CURDIR)/scripts/dev/devtools.sh -lint

##@ Testing
.PHONY: test
test: ## Run tests
	@$(PYTHON_BIN)/python -m unittest discover -s tests

##@ Cleanup
.PHONY: clean
clean: ## Clean up pychache and build artifacts
	@echo "Cleaning up pycache..."
	@find . -name "*.pyc" -delete >/dev/null 2>&1 || true
	@find . -name "__pycache__" -delete >/dev/null 2>&1 || true

SHELL=bash
.DEFAULT_GOAL := help
##@ Help

# The help target prints out all targets with their descriptions organized
# beneath their categories. The categories are represented by '##@' and the
# target descriptions by '##'. The awk commands is responsible for reading the
# entire set of makefiles included in this invocation, looking for lines of the
# file as xyz: ## something, and then pretty-format the target and help. Then,
# if there's a line with ##@ something, that gets pretty-printed as a category.
# More info on the usage of ANSI control characters for terminal formatting:
# https://en.wikipedia.org/wiki/ANSI_escape_code#SGR_parameters
# More info on the awk command:
# http://linuxcommand.org/lc3_adv_awk.php
.PHONY: help
help: ## Display this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

%:
	@: