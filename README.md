# Gateway
[![Build Status](https://github.com/go-kratos/gateway/workflows/Test/badge.svg?branch=main)](https://github.com/go-kratos/gateway/actions?query=branch%3Amain)
[![codecov](https://codecov.io/gh/go-kratos/gateway/branch/main/graph/badge.svg)](https://codecov.io/gh/go-kratos/gateway)

HTTP -> Proxy -> Router -> Middleware -> Client -> Selector -> Node

## Run
```bash
casdoor_endpoint=http://casdoor_endpoint:8000 \
redis_addr=redis_addr:6379 \
JWT_PUBKEY_PATH="./public.pem" \
kratos run
```

## 编写自定义中间件
1. 创建一个目录: ./middleware/routerfilter
2. 创建一个文件: ./middleware/routerfilter/routerfilter.go
3. 如果需要配置: : /api/gateway/middleware/routerfilter/routerfilter.proto
4. 实现接口
```go
package routerfilter

import "github.com/go-kratos/gateway/middleware"

func Middleware(c *config.Middleware) (middleware.Middleware, error) {
	return func(next http.RoundTripper) http.RoundTripper {
		return middleware.RoundTripperFunc(func(req *http.Request) (*http.Response, error) {
			// 在这里编写中间件逻辑
			// ...
			
			// 执行到这里时就意味着中间件已经执行完毕, 根据./cmd/gateway/config.yaml的中间件顺序继续执行下一个中间件
			return next.RoundTrip(req)
		}
	}
}
```

1. 当你需要提供给其他中间件或者全局使用时, 可以在`./api/gateway/config/v1/gateway.proto`配置通用的配置,然后在`func Middleware(c *config.Middleware) (middleware.Middleware, error) {} `使用`c.XXX` 来获取配置
2. 当你只需要你自身的配置的时候, 在`./api/gateway/middleware/` 创建, 例如 `routerfilter/v1/routerfilter.proto` 文件, 通过生成出的pb包来使用, 例如
```go
import v1 "github.com/go-kratos/gateway/api/gateway/middleware/routerfilter/v1"

options := &v1.RouterFilter{}`
````

5. 注册:
```go
package routerfilter
func init() {
	prometheus.MustRegister(requestsTotal, requestDuration)
	middleware.Register("router_filter", Middleware)
	fmt.Println("RouterFilter middleware initialized")
}

```

6. 添加中间件到主进程
```go
package main
import (
  _ "github.com/go-kratos/gateway/middleware/routerfilter" // 过滤中间件
)
```

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
* jwt: 与casdoor集成
* rbac: 与casdoor的集成, 使用到了redis来缓存casbin策略, 基于角色的接口的权限控制
* router_filter: 路由过滤器, 用于过滤掉不需要的路由

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

### RouterFilter
路由过滤器, 用于过滤掉不需要的路由, 目前只支持正则匹配, 不支持通配符匹配, 不支持前缀匹配, 不支持后缀匹配, 不支持路径参数匹配,
该 router_filter 中间件支持以下类型的路由规则：

1. 精确路径匹配
   规则示例 ：/v1/products
   匹配行为 ：仅匹配完全相同的路径
   代码依据 ：正则表达式直接编译路径为精确匹配模式 
2. 通配符匹配
   a. 单层通配符 (/*)
   规则示例 ：/v1/products/*
   匹配行为 ：匹配单级子路径（如 /v1/products/123）
   实现原理 ：正则表达式将 /* 转换为 [^/]+ 
   b. 多层通配符 (/**)
   规则示例 ：/v1/products/**
   匹配行为 ：匹配多级子路径（如 /v1/products/123/details）
   实现原理 ：正则表达式将 /** 转换为 .+ 
3. 路径参数捕获
   规则示例 ：/v1/products/{id}
   匹配行为 ：提取路径参数（如 id=123）
   实现原理 ：通过正则表达式命名捕获组 (?P<id>[^/]+) 
4. HTTP 方法限制
   规则示例 ：
    ```yaml
    - path: /v1/products
      methods: [GET, POST]
    ```
- path: /v1/products
  methods: [GET, POST]
  匹配行为 ：仅允许指定的 HTTP 方法
  实现原理 ：检查请求方法是否在允许列表中 
5. 混合规则（路径 + 方法）
   规则示例 ：
```yaml
- path: /v1/auth
  methods: [POST, OPTIONS]
```

- path: /v1/auth
  methods: [POST, OPTIONS]
  匹配行为 ：同时满足路径和方法条件的请求才会被放行
  实现原理 ：路径和方法检查在 PathMatcher.Match() 中联合执行 
6. CORS 预检请求自动放行
   规则示例 ：所有 OPTIONS 请求
   匹配行为 ：直接返回 CORS 响应头，跳过后续中间件
   实现原理 ：在中间件入口处特殊处理 OPTIONS 方法 

配置示例:
```yaml
middlewares:
  - name: router_filter
    options:
      "@type": type.googleapis.com/gateway.middleware.routerfilter.v1.RouterFilter
      rules:
        # 精确路径 + 方法限制
        - path: /v1/auth
          methods: [POST, OPTIONS]
        
        # 通配符匹配
        - path: /v1/products/**
          methods: [GET]
        
        # 路径参数捕获
        - path: /v1/orders/{order_id}
          methods: [GET, DELETE]
```

### JWT
证书使用`x509`生成,4096位大小,加密算法是RS256(RSA+SHA256),有效期20年. 
证书文件在`/cmd/gatway`目录下, 证书文件名为`public.pem`

### RBAC

目前使用了官方的casbin的redis插件来缓存策略, 不一定是Redis, 也可以是任何支持redis协议的`rpush`工具即可 
目前的redis实例是没有设置密码的, 如果需要设置密码, 可以修改`middleware/rbac/rbac.go`中的代码的`initEnforcer` 函数,
常用的函数如下:
- 无加密: redisadapter.NewAdapter
- 包含密码: func NewAdapterWithPassword(network string, address string, password string) (*Adapter, error)
- 包含用户和密码: func NewAdapterWithUser(network string, address string, username string, password string) (*Adapter, error)

```go
package rbac

import (
	"fmt"
	"github.com/casbin/casbin/v2"
	redisadapter "github.com/casbin/redis-adapter/v3"
)

func initEnforcer() {
	a, err := redisadapter.NewAdapter("tcp", RedisAddr)
	if err != nil {
		panic(fmt.Errorf("failed to initialize redis adapter: %v", err))
	}

	enforcer, err := casbin.NewSyncedCachedEnforcer("./rbac_model.conf", a)
	if err != nil {
		panic(fmt.Errorf("failed to initialize enforcer: %v", err))
	}
	syncedCachedEnforcer = enforcer

	// 初始化策略
	initPolicies(enforcer)
}

```

当前模型:
```
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act, eft

[role_definition]
g = _, _
g2 = _, _

[policy_effect]
e = some(where (p.eft == allow)) && !some(where (p.eft == deny))

[matchers]
m = g(r.sub, p.sub) && keyMatch2(r.obj, p.obj) && regexMatch(r.act, p.act) && !keyMatch2(r.obj, "/v1/auth")

```

策略:
```json
[
  {
    "value": "{\"PType\":\"p\",\"V0\":\"public\",\"V1\":\"/v1/auth\",\"V2\":\"POST\",\"V3\":\"allow\",\"V4\":\"\",\"V5\":\"\"}"
  },
  {
    "value": "{\"PType\":\"p\",\"V0\":\"user\",\"V1\":\"/v1/auth/profile\",\"V2\":\"GET\",\"V3\":\"allow\",\"V4\":\"\",\"V5\":\"\"}"
  },
  {
    "value": "{\"PType\":\"p\",\"V0\":\"user\",\"V1\":\"/v1/users/*\",\"V2\":\"(GET|POST|PATCH|DELETE)\",\"V3\":\"allow\",\"V4\":\"\",\"V5\":\"\"}"
  },
  {
    "value": "{\"PType\":\"p\",\"V0\":\"user\",\"V1\":\"/v1/cart*\",\"V2\":\"(GET|POST|DELETE)\",\"V3\":\"allow\",\"V4\":\"\",\"V5\":\"\"}"
  },
  {
    "value": "{\"PType\":\"p\",\"V0\":\"user\",\"V1\":\"/v1/checkout\",\"V2\":\"POST\",\"V3\":\"allow\",\"V4\":\"\",\"V5\":\"\"}"
  },
  {
    "value": "{\"PType\":\"p\",\"V0\":\"user\",\"V1\":\"/v1/order\",\"V2\":\"(GET|POST)\",\"V3\":\"allow\",\"V4\":\"\",\"V5\":\"\"}"
  },
  {
    "value": "{\"PType\":\"p\",\"V0\":\"merchant\",\"V1\":\"/v1/products*\",\"V2\":\"(POST|PUT|DELETE)\",\"V3\":\"allow\",\"V4\":\"\",\"V5\":\"\"}"
  },
  {
    "value": "{\"PType\":\"p\",\"V0\":\"merchant\",\"V1\":\"/v1/products/*/submit-audit\",\"V2\":\"POST\",\"V3\":\"allow\",\"V4\":\"\",\"V5\":\"\"}"
  },
  {
    "value": "{\"PType\":\"p\",\"V0\":\"admin\",\"V1\":\"/v1/categories*\",\"V2\":\"(POST|PUT|DELETE|PATCH)\",\"V3\":\"allow\",\"V4\":\"\",\"V5\":\"\"}"
  },
  {
    "value": "{\"PType\":\"p\",\"V0\":\"admin\",\"V1\":\"/v1/products/*/audit\",\"V2\":\"POST\",\"V3\":\"allow\",\"V4\":\"\",\"V5\":\"\"}"
  },
  {
    "value": "{\"PType\":\"p\",\"V0\":\"admin\",\"V1\":\"/v1/order/*/paid\",\"V2\":\"POST\",\"V3\":\"allow\",\"V4\":\"\",\"V5\":\"\"}"
  },
  {
    "value": "{\"PType\":\"p\",\"V0\":\"anyone\",\"V1\":\"/*\",\"V2\":\".*\",\"V3\":\"deny\",\"V4\":\"\",\"V5\":\"\"}"
  },
  {
    "value": "{\"PType\":\"g\",\"V0\":\"merchant\",\"V1\":\"user\",\"V2\":\"\",\"V3\":\"\",\"V4\":\"\",\"V5\":\"\"}"
  },
  {
    "value": "{\"PType\":\"g\",\"V0\":\"admin\",\"V1\":\"merchant\",\"V2\":\"\",\"V3\":\"\",\"V4\":\"\",\"V5\":\"\"}"
  },
  {
    "value": "{\"PType\":\"p\",\"V0\":\"user\",\"V1\":\"/v1/products\",\"V2\":\"GET\",\"V3\":\"allow\",\"V4\":\"\",\"V5\":\"\"}"
  }
]
```
