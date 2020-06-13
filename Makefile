GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
BUILD_DIR=_docker
TAG=1.0.0-snapshot
BINARY_NAME=$(BUILD_DIR)/main
MAIN_FILE=cmd/main.go
BENCH_OUT_DIR=_out
BENCH_N=0
BENCH_TIME=10s
BENCH_MEM_FILE=$(BENCH_OUT_DIR)/memprofile_$(BENCH_N).out
BENCH_CPU_FILE=$(BENCH_OUT_DIR)/cpuprofile_$(BENCH_N).out
BENCH_DIR=decoder

all: clean verify build docker
docker: build
	docker build $(BUILD_DIR) -t $(TAG)
build: deps
	CGO_ENABLED=0 GOARCH=amd64 GOOS=linux GO111MODULE=on $(GOBUILD) -o $(BINARY_NAME) -v $(MAIN_FILE)
verify: test bench
bench:
	mkdir -p $(BENCH_OUT_DIR)
	$(GOTEST) ./$(BENCH_DIR) -bench=. -benchtime $(BENCH_TIME) -benchmem -memprofile $(BENCH_MEM_FILE) -cpuprofile $(BENCH_CPU_FILE)
test: deps lint
	$(GOTEST) -race ./... -v
lint:
	go fmt ./...
	go vet ./...
	golint ./...
clean:
	$(GOCLEAN)
	rm -f $(BINARY_NAME)
	rm -f $(BENCH_DIR).test
deps:
	$(GOCMD) mod download
