.PHONY: test
test:
	go test -v ./...

.PHONY: coverage
coverage:
	go test ./... -coverprofile coverage.cov -coverpkg ./... || true
	go tool cover -func coverage.cov

.PHONY: clean
clean:
	rm coverage.cov
	