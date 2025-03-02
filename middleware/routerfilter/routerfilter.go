package routerfilter

import (
	"bytes"
	"fmt"
	config "github.com/go-kratos/gateway/api/gateway/config/v1"
	v1 "github.com/go-kratos/gateway/api/gateway/middleware/routerfilter/v1"
	"github.com/go-kratos/gateway/middleware"
	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

const (
	metricsNamespace = "gateway"
	metricsSubsystem = "routerfilter"
)

var (
	requestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: metricsSubsystem,
			Name:      "requests_total",
			Help:      "Total processed requests",
		},
		[]string{"matched", "method", "path"},
	)

	requestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Subsystem: metricsSubsystem,
			Name:      "request_duration_seconds",
			Help:      "Request processing duration",
			Buckets:   []float64{0.1, 0.5, 1, 2, 5},
		},
		[]string{"status"},
	)

	tracer = otel.Tracer("gateway/router_filter")
)

var (
	matched bool
	params  map[string]string
	rule    string
)

func init() {
	prometheus.MustRegister(requestsTotal, requestDuration)
	middleware.Register("router_filter", Middleware)
	fmt.Println("RouterFilter middleware initialized")
}

type Matcher interface {
	Match(*http.Request) (bool, map[string]string)
}

type PathMatcher struct {
	rawPattern    string
	regex         *regexp.Regexp
	methods       map[string]struct{}
	paramNames    []string
	wildcardLevel int // 0=exact, 1=single, 2=multi
}

func NewPathMatcher(pattern string, methods []string) (*PathMatcher, error) {
	// 增强路径匹配能力
	pattern = strings.SplitN(pattern, "?", 2)[0] // 忽略查询参数
	pattern = strings.TrimSuffix(pattern, "/")   // 统一路径格式
	// 解析路径参数和通配符
	paramRegex := regexp.MustCompile(`{(\w+)}`)
	matches := paramRegex.FindAllStringSubmatch(pattern, -1)
	paramNames := make([]string, 0, len(matches))
	for _, m := range matches {
		paramNames = append(paramNames, m[1])
	}

	// 确定通配符级别
	wildcardLevel := 0

	if strings.Contains(pattern, "/*") {
		wildcardLevel = 1
	} else if strings.Contains(pattern, "/**") {
		wildcardLevel = 2
	}

	// 构建正则表达式
	// 先处理更长的通配符（如 /**），避免替换冲突
	replacer := strings.NewReplacer(
		"/**", "/.*",
		"/*/", "/[^/]*/",
		"/*", "/[^/]*",
		"{", "(?P<",
		"}", ">[^/]*)",
	)
	regexPattern := "^" + replacer.Replace(pattern) + "$"

	compiled, err := regexp.Compile(regexPattern)
	if err != nil {
		return nil, fmt.Errorf("invalid pattern %q: %w", pattern, err)
	}

	methodSet := make(map[string]struct{})
	for _, m := range methods {
		methodSet[strings.ToUpper(m)] = struct{}{}
	}

	return &PathMatcher{
		rawPattern:    pattern,
		regex:         compiled,
		methods:       methodSet,
		paramNames:    paramNames,
		wildcardLevel: wildcardLevel,
	}, nil
}

func (m *PathMatcher) Match(req *http.Request) (bool, map[string]string) {
	// 统一格式：去除前后斜杠并转为小写
	path := strings.TrimSuffix(req.URL.Path, "/")
	if path == "" {
		path = "/"
	}
	// pattern := strings.TrimPrefix(strings.TrimSuffix(m.rawPattern, "/"), "/")

	// 方法检查
	if len(m.methods) > 0 {
		if _, ok := m.methods[req.Method]; !ok {
			return false, nil
		}
	}

	// 路径匹配
	match := m.regex.FindStringSubmatch(path)
	if len(match) == 0 {
		return false, nil
	}

	params := make(map[string]string)
	for i, name := range m.regex.SubexpNames() {
		if i > 0 && name != "" {
			params[name] = match[i]
		}
	}
	return true, params
}

func Middleware(c *config.Middleware) (middleware.Middleware, error) {
	options := &v1.RouterFilter{}
	if c.Options != nil {
		if err := anypb.UnmarshalTo(c.Options, options, proto.UnmarshalOptions{}); err != nil {
			return nil, fmt.Errorf("failed to unmarshal options: %w", err)
		}
	}

	// NewPathMatcher 返回错误（如正则表达式编译失败），阻止无效对象加入 matchers 数组
	matchers := make([]*PathMatcher, 0, len(options.Rules))
	for _, rule := range options.Rules {
		pm, err := NewPathMatcher(rule.Path, rule.Methods)
		if err != nil {
			return nil, fmt.Errorf("invalid rule %q: %w", rule.Path, err)
		}
		if pm == nil {
			return nil, fmt.Errorf("matcher for %q is nil", rule.Path)
		}
		matchers = append(matchers, pm)
	}

	return func(next http.RoundTripper) http.RoundTripper {
		return middleware.RoundTripperFunc(func(req *http.Request) (*http.Response, error) {
			// 添加CORS预处理
			if req.Method == "OPTIONS" {
				return &http.Response{
					StatusCode: http.StatusNoContent,
					Header: http.Header{
						"Access-Control-Allow-Origin":  []string{"*"},
						"Access-Control-Allow-Methods": []string{"GET, POST, PUT, DELETE, OPTIONS"},
						"Access-Control-Allow-Headers": []string{"*"},
						"Access-Control-Max-Age":       []string{"600"},
					},
				}, nil
			}

			start := time.Now()
			ctx, span := tracer.Start(req.Context(), "RouterFilter",
				trace.WithAttributes(
					attribute.String("http.method", req.Method),
					attribute.String("http.path", req.URL.Path),
				))
			for _, matcher := range matchers {
				if ok, _ := matcher.Match(req); ok {
					fmt.Println("matched")
					return next.RoundTrip(req.WithContext(ctx))
				}
			}

			defer func() {
				duration := time.Since(start).Seconds()
				status := "200"
				if resp, _ := ctx.Value("response").(*http.Response); resp != nil {
					status = fmt.Sprintf("%d", resp.StatusCode)
				}

				requestDuration.WithLabelValues(status).Observe(duration)
				requestsTotal.WithLabelValues(
					fmt.Sprintf("%t", matched),
					req.Method,
					req.URL.Path,
				).Inc()

				if matched {
					span.SetAttributes(
						attribute.String("match.rule", rule),
						attribute.Int("match.params_count", len(params)),
					)
				}
				span.End()
			}()

			fmt.Println("not matched")
			// 未匹配时的处理
			return newResponse(http.StatusForbidden, http.Header{
				"Content-Type": []string{"application/json"},
			}), nil
		})
	}, nil
}

func newResponse(statusCode int, header http.Header) *http.Response {
	return &http.Response{
		StatusCode: statusCode,
		Header:     header,
		Body:       io.NopCloser(bytes.NewBufferString(`{"code":403,"message":"access denied"}`)),
	}
}
