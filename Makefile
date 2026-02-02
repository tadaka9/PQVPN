# PQVPN Makefile

.PHONY: install dev-loop think new security-checks tests test

install:
	pip install -e ".[dev]"

dev-loop:
	./scripts/dev_loop.sh

think:
	./scripts/think.sh

new:
	./scripts/new.sh

security-checks:
	./scripts/security_checks.sh

tests:
	./scripts/run_tests.sh

test:
	@echo "Manual testing: Refer to docs/manual_test_checklist.md"