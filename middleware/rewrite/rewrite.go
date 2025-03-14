package rewrite

import (
	"log"
	"net/http"
	"path"
	"strings"

	config "github.com/go-kratos/gateway/api/gateway/config/v1"
	v1 "github.com/go-kratos/gateway/api/gateway/middleware/rewrite/v1"

	"github.com/go-kratos/gateway/middleware"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

func init() {
	middleware.Register("rewrite", Middleware)
}

func stripPrefix(origin string, prefix string) string {
	out := strings.TrimPrefix(origin, prefix)
	if out == "" {
		return "/"
	}
	if out[0] != '/' {
		return path.Join("/", out)
	}
	return out
}

func applyHeadersPolicy(header http.Header, policy *v1.HeadersPolicy) {
	if policy == nil {
		return
	}

	// 先处理删除
	for _, key := range policy.Remove {
		header.Del(key)
	}

	// 处理设置（覆盖已有值）
	for key, value := range policy.Set {
		header.Set(key, value)
	}

	// 处理添加（保留已有值）
	for key, value := range policy.Add {
		header.Add(key, value)
	}
}

func Middleware(c *config.Middleware) (middleware.Middleware, error) {
	options := &v1.Rewrite{}
	if c.Options != nil {
		if err := anypb.UnmarshalTo(c.Options, options, proto.UnmarshalOptions{Merge: true}); err != nil {
			return nil, err
		}
	}

	return func(next http.RoundTripper) http.RoundTripper {
		return middleware.RoundTripperFunc(func(req *http.Request) (*http.Response, error) {
			originalPath := req.URL.Path
			// originalHost := req.Host

			// 1. 处理前缀剥离
			if options.StripPrefix != nil {
				req.URL.Path = stripPrefix(req.URL.Path, options.GetStripPrefix())
			}

			// 2. 路径重写（支持保留方法名）
			if options.PathRewrite != nil {
				// 获取原始路径的方法名部分
				methodName := path.Base(originalPath)
				// 拼接新路径和方法名
				req.URL.Path = path.Join(*options.PathRewrite, methodName)
			}

			// 3. 主机重写
			if options.HostRewrite != nil {
				req.Host = *options.HostRewrite
				req.URL.Host = *options.HostRewrite
			}

			// 4. 处理请求头
			applyHeadersPolicy(req.Header, options.RequestHeadersRewrite)

			log.Printf("Rewritten path: %s -> %s", originalPath, req.URL.Path)

			// 5. 转发请求
			resp, err := next.RoundTrip(req)
			if err != nil {
				return nil, err
			}

			// 6. 处理响应头
			applyHeadersPolicy(resp.Header, options.ResponseHeadersRewrite)

			return resp, nil
		})
	}, nil
}
