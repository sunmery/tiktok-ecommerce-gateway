package middleware

import (
	"context"
	"io"
	"net/http"

	configv1 "github.com/go-kratos/gateway/api/gateway/config/v1"
)

type contextKey struct{ name string }

// RequestPathKey 用于存储原始请求路径的上下文键
var RequestPathKey = &contextKey{"RequestPath"}

// Factory is a middleware factory.
type Factory func(*configv1.Middleware) (Middleware, error)

// Middleware is handler middleware.
type Middleware func(http.RoundTripper) http.RoundTripper

// RoundTripperFunc is an adapter to allow the use of
// ordinary functions as HTTP RoundTripper.
type RoundTripperFunc func(*http.Request) (*http.Response, error)

// RoundTrip calls f(w, r).
func (f RoundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type (
	FactoryV2    func(*configv1.Middleware) (MiddlewareV2, error)
	MiddlewareV2 interface {
		Process(http.RoundTripper) http.RoundTripper
		io.Closer
	}
)

func WithRequestPath(ctx context.Context, path string) context.Context {
	return context.WithValue(ctx, RequestPathKey, path)
}

func RequestPathFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(RequestPathKey).(string); ok {
		return v
	}
	return ""
}

func wrapFactory(in Factory) FactoryV2 {
	return func(m *configv1.Middleware) (MiddlewareV2, error) {
		v, err := in(m)
		if err != nil {
			return nil, err
		}
		return v, nil
	}
}

func (f Middleware) Process(in http.RoundTripper) http.RoundTripper { return f(in) }
func (f Middleware) Close() error                                   { return nil }

type withCloser struct {
	process Middleware
	closer  io.Closer
}

func (w *withCloser) Process(in http.RoundTripper) http.RoundTripper { return w.process(in) }
func (w *withCloser) Close() error                                   { return w.closer.Close() }
func NewWithCloser(process Middleware, closer io.Closer) MiddlewareV2 {
	return &withCloser{
		process: process,
		closer:  closer,
	}
}

var EmptyMiddleware = emptyMiddleware{}

type emptyMiddleware struct{}

func (emptyMiddleware) Process(next http.RoundTripper) http.RoundTripper { return next }
func (emptyMiddleware) Close() error                                     { return nil }
