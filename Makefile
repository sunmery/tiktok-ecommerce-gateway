API_PROTO_FILES=$(shell find api -name *.proto)

.PHONY: api
# generate api proto
api:
	protoc --proto_path=./api \
	  --proto_path=./third_party \
 	  --go_out=paths=source_relative:./api \
	  $(API_PROTO_FILES)

ifndef VERSION
    $(error VERSION is not set)
endif
ifndef GATEWAY_PORT
    GATEWAY_PORT=8080
endif

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
	DOMAIN=your-domain.com
	openssl req -x509 -newkey rsa:4096 -nodes -keyout key.pem -out cert.pem -days 365 -subj "/CN=$(DOMAIN)"
