# Gateway
[![Build Status](https://github.com/go-kratos/gateway/workflows/Test/badge.svg?branch=main)](https://github.com/go-kratos/gateway/actions?query=branch%3Amain)
[![codecov](https://codecov.io/gh/go-kratos/gateway/branch/main/graph/badge.svg)](https://codecov.io/gh/go-kratos/gateway)

HTTP -> Proxy -> Router -> Middleware -> Client -> Selector -> Node

## Protocol
* HTTP -> HTTP  
* HTTP -> gRPC  
* gRPC -> gRPC  

## Encoding
* Protobuf Schemas

## Endpoint
* prefix: /api/echo/*
* path: /api/echo/hello
* regex: /api/echo/[a-z]+
* restful: /api/echo/{name}

## Middleware
* cors
* auth
* color
* logging
* tracing
* metrics
* ratelimit
* datacenter

### CORS

前端一般都要包含如下请求头:
```yaml
allowHeaders:
  - Authorization
  - Content-Type
  - X-Requested-With
  - DNT
  - Sec-Fetch-Dest
  - Sec-Fetch-Mode
  - Sec-Fetch-Site

```
站点规则如下:
请求来源	配置项	是否允许
- http://a.localhost:3000	.localhost	✅
- http://localhost:8080	.localhost	✅
- http://x.y.localhost	*.localhost	✅
- http://evil.localhost.com	.localhost	❌
- http://127.0.0.1:3000	127.0.0.1:3000	✅
如果需要修改, 可以修改`middleware/cors/cors.go`中的代码的`isOriginAllowed` 函数
