.PHONY: check-firewall e2e-pocketbase test

check-firewall:
	@bash scripts/check-firewall.sh

e2e-pocketbase:
	@bash scripts/e2e-pocketbase.sh

test:
	@go test -count=1 ./...
