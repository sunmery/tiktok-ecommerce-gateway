package routerfilter

import (
	config "github.com/go-kratos/gateway/api/gateway/config/v1"
	v1 "github.com/go-kratos/gateway/api/gateway/middleware/routerfilter/v1"
	"github.com/go-kratos/gateway/middleware"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPathMatcher(t *testing.T) {
	// 测试用例集（包含通配符、路径参数等场景）
	testCases := []struct {
		name      string
		pattern   string
		methods   []string
		reqPath   string
		reqMethod string
		expected  bool
	}{
		{
			"精确匹配GET方法",
			"/api/v1/users",
			[]string{"GET"},
			"/api/v1/users",
			"GET",
			true,
		},
		{
			"路径参数匹配",
			"/api/v1/users/{id}/profile",
			nil,
			"/api/v1/users/123/profile",
			"POST",
			true,
		},
		{
			"通配符匹配（单级）",
			"/static/*",
			nil,
			"/static/css/style.css",
			"GET",
			true,
		},
		{
			"多级通配符匹配",
			"/docs/**",
			nil,
			"/docs/chapter1/section1.1",
			"GET",
			true,
		},
		{
			"多级通配符匹配2",
			"/docs/**",
			nil,
			"/docs/.*$",
			"GET",
			true,
		},
		{
			"方法不匹配",
			"/api/delete",
			[]string{"DELETE"},
			"/api/delete",
			"POST",
			false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			matcher, err := NewPathMatcher(tc.pattern, tc.methods)
			assert.NoError(t, err)

			req := httptest.NewRequest(tc.reqMethod, tc.reqPath, nil)
			matched, _ := matcher.Match(req)
			assert.Equal(t, tc.expected, matched)
		})
	}
}

func TestMiddleware_Metrics(t *testing.T) {
	// 初始化Prometheus注册表
	registry := prometheus.NewRegistry()
	registry.MustRegister(requestsTotal, requestDuration)

	// 创建测试中间件配置
	conf := &config.Middleware{
		Options: mustNewAny(&v1.RouterFilter{
			Rules: []*v1.Rule{
				{Path: "/api/*", Methods: []string{"GET"}},
			},
		}),
	}

	// 创建中间件链
	mw, err := Middleware(conf)
	assert.NoError(t, err)

	// 模拟下游处理器
	next := middleware.RoundTripperFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200}, nil
	})

	testCases := []struct {
		name         string
		request      *http.Request
		expectMetric bool
	}{
		{
			"匹配请求应记录指标",
			httptest.NewRequest("GET", "/api/users", nil),
			true,
		},
		{
			"不匹配请求应记录拒绝指标",
			httptest.NewRequest("POST", "/api/users", nil),
			false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// 执行中间件
			resp, _ := mw(next).RoundTrip(tc.request)

			// 验证响应状态码
			if tc.expectMetric {
				assert.Equal(t, 200, resp.StatusCode)
			} else {
				assert.Equal(t, 403, resp.StatusCode)
			}

			// 验证Prometheus指标
			metricFamilies, _ := registry.Gather()
			assert.Greater(t, len(metricFamilies), 0)
		})
	}
}

func TestTracingIntegration(t *testing.T) {
	// 配置追踪收集器
	exporter := tracetest.NewInMemoryExporter()
	_ = sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
	)

	testRequest := httptest.NewRequest("GET", "/api/traced", nil)

	// 执行中间件处理
	mw, _ := Middleware(&config.Middleware{})
	_, _ = mw(nil).RoundTrip(testRequest)

	// 验证追踪属性
	spans := exporter.GetSpans()
	assert.Greater(t, len(spans), 0)
	attrs := spans[0].Attributes
	assert.Contains(t, attrs, attribute.String("http.method", "GET"))
	assert.Contains(t, attrs, attribute.String("http.path", "/api/traced"))
}

func TestCORSHandling(t *testing.T) {
	// 创建OPTIONS请求
	req := httptest.NewRequest("OPTIONS", "/api/data", nil)

	// 执行中间件
	mw, _ := Middleware(&config.Middleware{})
	resp, _ := mw(nil).RoundTrip(req)

	// 验证CORS头信息
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	assert.Equal(t, "*", resp.Header.Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "600", resp.Header.Get("Access-Control-Max-Age"))
}

func TestAccessDeniedResponse(t *testing.T) {
	req := httptest.NewRequest("POST", "/unauthorized", nil)

	mw, _ := Middleware(&config.Middleware{})
	resp, _ := mw(nil).RoundTrip(req)

	// 验证拒绝响应格式
	assert.Equal(t, 403, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	body := make([]byte, 100)
	_, err := resp.Body.Read(body)
	if err != nil {
		return
	}
	assert.Contains(t, string(body), `"access denied"`)
}

// 辅助函数：创建Any类型配置
func mustNewAny(pb proto.Message) *anypb.Any {
	a, err := anypb.New(pb)
	if err != nil {
		panic(err)
	}
	return a
}
