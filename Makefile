.PHONY: test
test:
	go test -v ./...

.PHONY: coverage
coverage:
	go test ./... -coverprofile to_filter.cov -coverpkg ./... || true
	grep -v "test_utils" to_filter.cov > coverage.cov
	rm to_filter.cov || true
	go tool cover -func coverage.cov

.PHONY: clean
clean:
	rm coverage.cov


.PHONY: install-golangci-lint
install-golangci-lint:
	@echo "Installing golangci-lint..."
	@curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/HEAD/install.sh | sh -s -- -b $$(go env GOPATH)/bin v2.6.1
	@echo "golangci-lint installed successfully!"
	@golangci-lint --version

.PHONY: check-golangci-lint
check-golangci-lint:
	@which golangci-lint > /dev/null || (echo "golangci-lint not found. Run 'make install-golangci-lint' to install it." && exit 1)

.PHONY: go-lint
go-lint:
	@which golangci-lint > /dev/null || (echo "golangci-lint not found. Installing..." && $(MAKE) install-golangci-lint)
	golangci-lint run --config .golangci.yml

.PHONY: go-lint-fix
go-lint-fix:
	@which golangci-lint > /dev/null || (echo "golangci-lint not found. Installing..." && $(MAKE) install-golangci-lint)
	golangci-lint run --config .golangci.yml --fix
