package ip

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	config "github.com/go-kratos/gateway/api/gateway/config/v1"
	"github.com/go-kratos/kratos/v2/log"
	"github.com/stretchr/testify/assert"
)

func TestMain(m *testing.M) {
	// 设置日志输出到标准输出
	log.SetLogger(log.NewStdLogger(os.Stdout))
	os.Exit(m.Run())
}

func TestMiddleware(t *testing.T) {
	// 创建一个测试配置
	cfg := &config.Middleware{}

	// 创建IP中间件
	mw, err := Middleware(cfg)
	assert.NoError(t, err)
	assert.NotNil(t, mw)

	// 创建一个模拟的RoundTripper，用于验证请求头是否被正确设置
	mockTransport := &mockRoundTripper{}

	// 将IP中间件应用到模拟的RoundTripper
	transport := mw(mockTransport)

	// 测试场景1: 使用X-Real-IP头
	req1 := httptest.NewRequest("GET", "http://example.com", nil)
	req1.Header.Set(XRealIP, "192.168.1.1")
	resp1, err := transport.RoundTrip(req1)
	assert.NoError(t, err)
	assert.Equal(t, "192.168.1.1", mockTransport.lastRequest.Header.Get(ClientIPHeader))
	assert.Equal(t, http.StatusOK, resp1.StatusCode)

	// 测试场景2: 使用X-Forwarded-For头
	req2 := httptest.NewRequest("GET", "http://example.com", nil)
	req2.Header.Set(XForwardedFor, "10.0.0.1, 10.0.0.2")
	resp2, err := transport.RoundTrip(req2)
	assert.NoError(t, err)
	assert.Equal(t, "10.0.0.1", mockTransport.lastRequest.Header.Get(ClientIPHeader))
	assert.Equal(t, http.StatusOK, resp2.StatusCode)

	// 测试场景3: 使用RemoteAddr
	req3 := httptest.NewRequest("GET", "http://example.com", nil)
	req3.RemoteAddr = "172.16.0.1:12345"
	resp3, err := transport.RoundTrip(req3)
	assert.NoError(t, err)
	assert.Equal(t, "172.16.0.1", mockTransport.lastRequest.Header.Get(ClientIPHeader))
	assert.Equal(t, http.StatusOK, resp3.StatusCode)

	// 测试场景4: 没有任何IP信息
	req4 := httptest.NewRequest("GET", "http://example.com", nil)
	req4.RemoteAddr = ""
	resp4, err := transport.RoundTrip(req4)
	assert.NoError(t, err)
	assert.Equal(t, "", mockTransport.lastRequest.Header.Get(ClientIPHeader))
	assert.Equal(t, http.StatusOK, resp4.StatusCode)
}

func TestGetClientIP(t *testing.T) {
	// 测试X-Real-IP
	req1 := httptest.NewRequest("GET", "http://example.com", nil)
	req1.Header.Set(XRealIP, "192.168.1.1")
	ip1 := getClientIP(req1)
	assert.Equal(t, "192.168.1.1", ip1)

	// 测试X-Forwarded-For
	req2 := httptest.NewRequest("GET", "http://example.com", nil)
	req2.Header.Set(XForwardedFor, "10.0.0.1, 10.0.0.2")
	ip2 := getClientIP(req2)
	assert.Equal(t, "10.0.0.1", ip2)

	// 测试RemoteAddr
	req3 := httptest.NewRequest("GET", "http://example.com", nil)
	req3.RemoteAddr = "172.16.0.1:12345"
	ip3 := getClientIP(req3)
	assert.Equal(t, "172.16.0.1", ip3)

	// 测试没有任何IP信息
	req4 := httptest.NewRequest("GET", "http://example.com", nil)
	req4.RemoteAddr = ""
	ip4 := getClientIP(req4)
	assert.Equal(t, "", ip4)
}

func TestIsPrivateIP(t *testing.T) {
	// 测试私有IP
	assert.True(t, IsPrivateIP("10.0.0.1"))
	assert.True(t, IsPrivateIP("172.16.0.1"))
	assert.True(t, IsPrivateIP("192.168.1.1"))
	assert.True(t, IsPrivateIP("127.0.0.1"))

	// 测试公共IP
	assert.False(t, IsPrivateIP("8.8.8.8"))
	assert.False(t, IsPrivateIP("114.114.114.114"))

	// 测试无效IP
	assert.False(t, IsPrivateIP("invalid-ip"))
}

func TestFormatClientIP(t *testing.T) {
	// 测试有效IP
	req1 := httptest.NewRequest("GET", "http://example.com", nil)
	req1.Header.Set(XRealIP, "192.168.1.1")
	formatted1 := FormatClientIP(req1)
	assert.Equal(t, "192.168.1.1", formatted1)

	// 测试无效IP
	req2 := httptest.NewRequest("GET", "http://example.com", nil)
	req2.RemoteAddr = ""
	formatted2 := FormatClientIP(req2)
	assert.Equal(t, "unknown", formatted2)
}

// 模拟的RoundTripper，用于测试
type mockRoundTripper struct {
	lastRequest *http.Request
}

func (m *mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	m.lastRequest = req
	// 返回一个模拟的响应
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       http.NoBody,
	}, nil
}
