.PHONY: setup test type-check lint format format-check clean test-integration build

setup:
	swift package resolve

test:
	swift test

type-check:
	swift build

lint:
	@if command -v swiftlint >/dev/null 2>&1; then \
		swiftlint lint --strict; \
	else \
		echo "swiftlint not installed - skipping"; \
	fi

format:
	@if command -v swiftformat >/dev/null 2>&1; then \
		swiftformat .; \
	else \
		echo "swiftformat not installed - skipping"; \
	fi

format-check:
	@if command -v swiftformat >/dev/null 2>&1; then \
		swiftformat --lint .; \
	else \
		echo "swiftformat not installed - skipping"; \
	fi

test-integration:
	swift test --filter BetterAuthTests.IntegrationTests

build:
	swift build -c release

clean:
	swift package clean
	rm -rf .build
