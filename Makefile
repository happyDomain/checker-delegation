CHECKER_NAME := checker-delegation
CHECKER_IMAGE := happydomain/$(CHECKER_NAME)
CHECKER_VERSION ?= custom-build

CHECKER_SOURCES := main.go $(wildcard checker/*.go)

GO_LDFLAGS := -X main.Version=$(CHECKER_VERSION)

.PHONY: all plugin docker test clean

all: $(CHECKER_NAME)

$(CHECKER_NAME): $(CHECKER_SOURCES)
	go build -tags standalone -ldflags "$(GO_LDFLAGS)" -o $@ .

plugin: $(CHECKER_NAME).so

$(CHECKER_NAME).so: $(CHECKER_SOURCES) $(wildcard plugin/*.go)
	go build -buildmode=plugin -ldflags "$(GO_LDFLAGS)" -o $@ ./plugin/

docker:
	docker build --build-arg CHECKER_VERSION=$(CHECKER_VERSION) -t $(CHECKER_IMAGE) .

test:
	go test -tags standalone ./...

clean:
	rm -f $(CHECKER_NAME) $(CHECKER_NAME).so
