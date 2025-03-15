package querytobody

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"

	config "github.com/go-kratos/gateway/api/gateway/config/v1"
	"github.com/go-kratos/gateway/middleware"
)

func init() {
	middleware.Register("query_to_body", Middleware)
}

func Middleware(c *config.Middleware) (middleware.Middleware, error) {
	return func(next http.RoundTripper) http.RoundTripper {
		return middleware.RoundTripperFunc(func(req *http.Request) (*http.Response, error) {
			// 强制转换非POST方法为POST
			if req.Method != http.MethodPost {
				req.Method = http.MethodPost // 关键修复点
			}

			// 转换查询参数到body
			if req.URL.Query() != nil {
				queryParams := make(map[string]interface{})
				for k, v := range req.URL.Query() {
					if len(v) > 1 {
						queryParams[k] = v
					} else {
						queryParams[k] = v[0]
					}
				}

				if jsonData, err := json.Marshal(queryParams); err == nil {
					req.Body = io.NopCloser(bytes.NewReader(jsonData))
					req.ContentLength = int64(len(jsonData))
					req.Header.Set("Content-Type", "application/json")
				}
				req.URL.RawQuery = "" // 清除查询参数
			}
			return next.RoundTrip(req)
		})
	}, nil
}
