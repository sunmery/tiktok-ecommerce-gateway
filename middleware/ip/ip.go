package ip

import (
	"net"
	"net/http"
	"strings"

	config "github.com/go-kratos/gateway/api/gateway/config/v1"
	"github.com/go-kratos/gateway/middleware"
	"github.com/go-kratos/kratos/v2/log"
)

// 定义IP相关的常量
const (
	// ClientIPHeader 是存储客户端IP的请求头
	ClientIPHeader = "X-Client-IP"
	// XRealIP 是一些代理服务器设置的包含客户端真实IP的请求头
	XRealIP = "X-Real-IP"
	// XForwardedFor 是代理服务器设置的包含请求经过的IP链的请求头
	XForwardedFor = "X-Forwarded-For"
)

func Init() {
	middleware.Register("ip", Middleware)
	log.Info("[IP] 中间件初始化完成")
}

// Middleware 创建一个收集客户端IP的中间件
func Middleware(c *config.Middleware) (middleware.Middleware, error) {
	return func(next http.RoundTripper) http.RoundTripper {
		return middleware.RoundTripperFunc(func(req *http.Request) (*http.Response, error) {
			// 获取客户端真实IP
			clientIP := getClientIP(req)

			// 记录是否成功收集到客户端IP
			if clientIP == "" {
				log.Warnf("[IP] 未能从请求中收集到客户端IP, URL: %s", req.URL.Path)
			} else {
				log.Infof("[IP] 成功收集到客户端IP: %s, URL: %s", clientIP, req.URL.Path)
			}

			// 将客户端IP添加到请求头中
			req.Header.Set(ClientIPHeader, clientIP)

			// 继续处理请求
			return next.RoundTrip(req)
		})
	}, nil
}

// getClientIP 从请求中提取客户端真实IP地址
// 优先级: X-Real-IP > X-Forwarded-For的第一个IP > RemoteAddr
func getClientIP(req *http.Request) string {
	// 1. 尝试从X-Real-IP头获取
	ip := req.Header.Get(XRealIP)
	if ip != "" {
		return ip
	}

	// 2. 尝试从X-Forwarded-For头获取第一个IP
	ip = req.Header.Get(XForwardedFor)
	if ip != "" {
		// X-Forwarded-For格式可能是: client, proxy1, proxy2
		// 我们需要获取第一个IP，即客户端IP
		parts := strings.Split(ip, ",")
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}

	// 3. 使用RemoteAddr
	if req.RemoteAddr != "" {
		// RemoteAddr格式为: IP:port
		ip, _, err := net.SplitHostPort(req.RemoteAddr)
		if err == nil {
			return ip
		}
		// 如果解析失败，直接返回RemoteAddr
		return req.RemoteAddr
	}

	return ""
}

// IsPrivateIP 检查IP是否为私有IP地址
func IsPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	// 如果是IPv4地址，net.ParseIP返回的是16字节长度的切片
	// 对于IPv4地址，前12字节是0，后4字节才是实际的IP地址
	// 需要使用To4()方法获取4字节的IPv4地址
	ipv4 := ip.To4()
	if ipv4 == nil {
		// 如果不是IPv4地址，则使用Go 1.17+提供的IsPrivate方法
		// 如果运行环境不支持IsPrivate方法，可以实现IPv6私有地址检查逻辑
		return false
	}

	// 检查是否为私有IP范围
	// 10.0.0.0/8
	if ipv4[0] == 10 {
		return true
	}
	// 172.16.0.0/12
	if ipv4[0] == 172 && ipv4[1] >= 16 && ipv4[1] <= 31 {
		return true
	}
	// 192.168.0.0/16
	if ipv4[0] == 192 && ipv4[1] == 168 {
		return true
	}
	// 127.0.0.0/8
	if ipv4[0] == 127 {
		return true
	}

	return false
}

// FormatClientIP 格式化客户端IP地址
func FormatClientIP(req *http.Request) string {
	clientIP := getClientIP(req)
	if clientIP == "" {
		return "unknown"
	}
	return clientIP
}
