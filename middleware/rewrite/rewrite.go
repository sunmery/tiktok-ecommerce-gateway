package rewrite

import (
	"net/http"
	"path"
	"strings"
	"unicode"

	config "github.com/go-kratos/gateway/api/gateway/config/v1"
	v1 "github.com/go-kratos/gateway/api/gateway/middleware/rewrite/v1"
	"github.com/go-kratos/gateway/middleware"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

func init() {
	middleware.Register("rewrite", Middleware)
}

func smartCamelCase(path string) string {
	parts := strings.Split(path, "/")
	if len(parts) < 3 {
		return path
	}

	// 保留前缀 v1/products 不变
	preserved := parts[:3]
	rest := parts[3:]

	var camelParts []string
	for _, p := range rest {
		if p == "" {
			continue
		}
		// 处理连续大写字母（如ID→Id）
		runes := []rune(p)
		var builder strings.Builder
		for i := 0; i < len(runes); i++ {
			if i > 0 && unicode.IsUpper(runes[i]) && unicode.IsLower(runes[i-1]) {
				builder.WriteRune(unicode.ToLower(runes[i]))
			} else {
				if i == 0 {
					builder.WriteRune(unicode.ToUpper(runes[i]))
				} else {
					builder.WriteRune(runes[i])
				}
			}
		}
		camelParts = append(camelParts, builder.String())
	}
	return strings.Join(append(preserved, camelParts...), "/")
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
			// 路径处理流程
			if options.StripPrefix != nil {
				req.URL.Path = strings.TrimPrefix(req.URL.Path, options.GetStripPrefix())
			}

			if options.CamelCaseConversion {
				req.URL.Path = smartCamelCase(req.URL.Path)
			}

			if options.PathRewrite != nil {
				req.URL.Path = path.Join(*options.PathRewrite, req.URL.Path)
			}

			// 强制方法转换（兼容旧配置）
			if options.MethodRewrite != nil {
				req.Method = *options.MethodRewrite
			}

			return next.RoundTrip(req)
		})
	}, nil
}
