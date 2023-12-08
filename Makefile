.PHONY: test
test:
	go test -v ./...

.PHONY: coverage
coverage:
	go test ./... -coverprofile coverage.cov -coverpkg ./... || true
	grep -v "_mock.go" coverage.cov > coverage_no_mocks.cov && mv coverage_no_mocks.cov coverage.cov
	grep -v "test/" coverage.cov > coverage_no_mocks.cov && mv coverage_no_mocks.cov coverage.cov
	go tool cover -func coverage.cov

.PHONY: clean
clean:
	rm coverage.cov