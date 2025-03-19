API_PROTO_FILES=$(shell find api -name *.proto)

.PHONY: api
# generate api proto
api:
	protoc --proto_path=./api \
	  --proto_path=./third_party \
 	  --go_out=paths=source_relative:./api \
	  $(API_PROTO_FILES)

REPOSITORY ?= ccr.ccs.tencentyun.com/kratos/gateway
GOIMAGE ?= golang:1.24.0-alpine3.21
GATEWAY_PORT ?= 8080
PLATFORM_1 ?= linux/amd64
PLATFORM_2 ?= linux/arm64

.PHONY: build
build:
	docker buildx build . \
      --progress=plain \
      -t $(REPOSITORY):$(VERSION) \
      --build-arg CGOENABLED=0 \
      --build-arg GOIMAGE=$(GOIMAGE) \
      --build-arg VERSION=$(VERSION) \
      --build-arg GATEWAY_PORT=$(GATEWAY_PORT) \
      --platform $(PLATFORM_1),$(PLATFORM_2) \
      --push

https:
	chmod +x cmd/gateway/dynamic-config/tls/generate-cert.sh && cmd/gateway/dynamic-config/tls//generate-cert.sh
