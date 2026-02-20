.PHONY: build test lint clean

BINARY := cs-eucaptcha-bouncer
CMD     := ./cmd/cs-eucaptcha-bouncer

build:
	go build -o $(BINARY) $(CMD)

test:
	go test ./...

lint:
	go vet ./...

clean:
	rm -f $(BINARY)
