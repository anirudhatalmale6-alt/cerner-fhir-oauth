# Makefile — the only commands you need.
#
#   make keygen   generate an RSA keypair (private stays local, public you upload)
#   make jwks     print the public key as a JWKS (optional, if registering by JWKS URL)
#   make deps     download Go module dependencies
#   make build    compile the CLI to ./bin/cerner-fhir-oauth
#   make run      build + run using values from your .env file
#   make test     run the unit tests
#   make clean    remove build artifacts

BINARY := bin/cerner-fhir-oauth
KEY_DIR := keys

.PHONY: keygen jwks deps build run test clean

keygen:
	@mkdir -p $(KEY_DIR)
	@echo ">> Generating 2048-bit RSA private key -> $(KEY_DIR)/private.pem"
	@openssl genrsa -out $(KEY_DIR)/private.pem 2048
	@echo ">> Extracting public key -> $(KEY_DIR)/public.pem"
	@openssl rsa -in $(KEY_DIR)/private.pem -pubout -out $(KEY_DIR)/public.pem
	@echo ">> Done. Upload $(KEY_DIR)/public.pem in the Cerner Code Console."

# Convert the public key into a one-key JWKS document (RS384). Handy if the
# console asks for a JWKS URL instead of a pasted public key — host jwks.json
# somewhere reachable and give the console that URL.
jwks:
	@go run ./tools/jwks $(KEY_DIR)/public.pem

deps:
	go mod tidy

build: deps
	@mkdir -p bin
	go build -o $(BINARY) .

run: build
	./$(BINARY)

test:
	go test ./...

clean:
	rm -rf bin
