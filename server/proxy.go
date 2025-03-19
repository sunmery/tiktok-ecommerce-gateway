package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"math"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/go-kratos/gateway/constants"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/go-kratos/kratos/v2/log"
)

var (
	readHeaderTimeout = time.Second * 10
	readTimeout       = time.Second * 15
	writeTimeout      = time.Second * 15
	idleTimeout       = time.Second * 120
)

func init() {
	var err error
	if v := os.Getenv(constants.ProxyReadHeaderTimeout); v != "" {
		if readHeaderTimeout, err = time.ParseDuration(v); err != nil {
			panic(err)
		}
	}
	if v := os.Getenv(constants.ProxyReadTimeout); v != "" {
		if readTimeout, err = time.ParseDuration(v); err != nil {
			panic(err)
		}
	}
	if v := os.Getenv(constants.ProxyWriteTimeout); v != "" {
		if writeTimeout, err = time.ParseDuration(v); err != nil {
			panic(err)
		}
	}
	if v := os.Getenv(constants.ProxyIdleTimeout); v != "" {
		if idleTimeout, err = time.ParseDuration(v); err != nil {
			panic(err)
		}
	}
}

// ProxyServer is a proxy server.
type ProxyServer struct {
	*http.Server
	h3Server  *http3.Server
	useTLS    bool
	useH3     bool
	httpPort  string
	http3Port string
}

// NewProxy new a gateway server.
func NewProxy(handler http.Handler) *ProxyServer {
	useTLS := os.Getenv(constants.UseTLS) == "true"
	useH3 := os.Getenv(constants.UseHttp3) == "true"
	httpPort := os.Getenv(constants.HTTPPort)
	http3Port := os.Getenv(constants.HTTP3Port)
	if httpPort == "" {
		httpPort = constants.DefaultHTTPPort
	}
	if http3Port == "" {
		http3Port = constants.DefaultHTTP3Port
	}

	var tlsConfig *tls.Config

	if useTLS {
		certFile := os.Getenv(constants.CrtFile)
		keyFile := os.Getenv(constants.KeyFile)

		// 获取当前工作目录
		wd, _ := os.Getwd()
		log.Infof("当前工作目录: %s", wd)
		log.Infof("certFile绝对路径: %s", filepath.Join(wd, certFile))
		log.Infof("keyFile绝对路径: %s", filepath.Join(wd, keyFile))

		if certFile == "" || keyFile == "" {
			log.Fatal("当UseTLS为true时，必须设置certFile和keyFile环境变量")
		}

		// 检查文件存在性
		if !fileExists(certFile) {
			log.Fatalf("证书文件不存在: %s", certFile)
		}
		if !fileExists(keyFile) {
			log.Fatalf("私钥文件不存在: %s", keyFile)
		}

		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			log.Fatalf("证书加载失败: %v (certFile=%s, keyFile=%s)", err, certFile, keyFile)
		}

		// TLS配置（兼容HTTP/3）
		tlsConfig = &tls.Config{
			Certificates:           []tls.Certificate{cert},
			NextProtos:             []string{"h3", "h2", "http/1.1"},   // 协议优先级顺序
			MinVersion:             tls.VersionTLS13,                   // 强制TLS 1.3
			SessionTicketsDisabled: false,                              // 0-RTT 启用会话票据
			ClientSessionCache:     tls.NewLRUClientSessionCache(1000), // 0-RTT
			CipherSuites: []uint16{
				tls.TLS_AES_128_GCM_SHA256,
				tls.TLS_AES_256_GCM_SHA384,
				tls.TLS_CHACHA20_POLY1305_SHA256,
			},
			CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP384},
			// ClientAuth:       tls.NoClientCert,                         // 不验证客户端证书
			// InsecureSkipVerify: false,                                    // 验证客户端证书
		}
	}

	// 包装原始handler
	wrappedHandler := altSvcMiddleware(handler, http3Port)

	ps := &ProxyServer{
		Server: &http.Server{
			Addr:              httpPort,                                        // TCP for HTTP/1.1 & HTTP/2
			TLSConfig:         tlsConfig,                                       // 启用 TLS 时支持 HTTP/2 over TLS
			Handler:           h2c.NewHandler(wrappedHandler, &http2.Server{}), // 处理 HTTP/2 明文或 HTTPS
			ReadTimeout:       readTimeout,
			ReadHeaderTimeout: readHeaderTimeout,
			WriteTimeout:      writeTimeout,
			IdleTimeout:       idleTimeout,
		},
		h3Server: &http3.Server{
			Addr: http3Port, // HTTP/3 UDP端口
		},
		httpPort:  httpPort,
		http3Port: http3Port,
		useTLS:    useTLS,
		useH3:     useH3,
	}

	if useH3 && tlsConfig != nil {
		// 配置QUIC参数
		quicConfig := &quic.Config{
			MaxIdleTimeout:             time.Minute * 3,  // 连接最大空闲时间
			KeepAlivePeriod:            time.Second * 15, // 心跳检测间隔
			MaxIncomingStreams:         500,              // 最大并发流数量
			MaxIncomingUniStreams:      100,              // 最大单向流数量
			EnableDatagrams:            true,             // 启用QUIC Datagram支持
			HandshakeIdleTimeout:       time.Second * 3,  // 握手超时
			DisablePathMTUDiscovery:    false,            // 启用PMTUD
			MaxStreamReceiveWindow:     1 << 24,          // 16MB
			MaxConnectionReceiveWindow: 1 << 25,          // 32MB
			InitialStreamReceiveWindow: 6 * 1024 * 1024,  // 6MB
			// MaxStreamReceiveWindow:         16 * 1024 * 1024, // 16MB
			InitialConnectionReceiveWindow: 8 * 1024 * 1024, // 8MB
			// MaxConnectionReceiveWindow:     32 * 1024 * 1024, // 32MB
		}

		// 独立监听 HTTP/3 请求
		ps.h3Server = &http3.Server{
			Addr:       http3Port, // UDP for HTTP/3
			TLSConfig:  tlsConfig,
			Handler:    handler,
			QUICConfig: quicConfig,
		}
	}

	return ps
}

// Start the server.
func (s *ProxyServer) Start(ctx context.Context) error {
	log.Infof("proxy listening on %s (HTTP/3:%v)", s.Addr, s.useH3)

	// 防火墙检测逻辑
	if s.useH3 {
		log.Warnf("请确认防火墙已开放UDP %s 端口（云服务器需配置安全组）", s.http3Port)
		if strings.HasPrefix(s.http3Port, ":") {
			port := strings.TrimPrefix(s.http3Port, ":")
			if _, err := strconv.Atoi(port); err == nil && port >= "1024" {
				log.Warnf("HTTP/3端口 %s 高于1024，部分浏览器可能拒绝Alt-Svc声明", port)
			}
		}
	}

	if s.h3Server != nil {
		go func() {
			defer func() {
				if err := recover(); err != nil {
					log.Errorf("HTTP/3服务崩溃: %v", err)
				}
			}()

			// 重试机制（最多3次）
			for retry := 0; retry < 3; retry++ {
				// 创建UDP监听器
				udpAddr, err := net.ResolveUDPAddr("udp", s.http3Port)
				if err != nil {
					log.Errorf("解析UDP地址失败: %v", err)
					return
				}
				conn, err := net.ListenUDP("udp", udpAddr)
				if err != nil {
					log.Errorf("创建UDP监听失败: %v", err)
					return
				}
				defer conn.Close()

				// 创建QUIC传输层
				transport := &quic.Transport{
					Conn: conn,
				}
				defer transport.Close()

				// 使用传输层创建早期监听器（EarlyListener）
				listener, err := transport.ListenEarly(s.h3Server.TLSConfig, s.h3Server.QUICConfig)
				if err != nil {
					log.Errorf("创建QUIC早期监听器失败: %v", err)
					return
				}
				defer listener.Close()

				// 使用HTTP/3服务器处理QUIC连接
				// if err := s.h3Server.ServeListener(listener); err != nil {
				// 	log.Errorf("HTTP/3 server error: %v", err)
				// }
				if err := s.h3Server.ServeListener(listener); err != nil {
					log.Errorf("HTTP/3服务错误(重试 %d/3): %v", retry+1, err)
					time.Sleep(time.Second * time.Duration(math.Pow(2, float64(retry))))
					continue
				}
				break
			}
		}()
	}
	// TCP服务协议协商检查
	s.Server.ConnState = func(conn net.Conn, state http.ConnState) {
		if state == http.StateHijacked {
			if tlsConn, ok := conn.(*tls.Conn); ok {
				state := tlsConn.ConnectionState()
				log.Debugf("协商协议: %s", state.NegotiatedProtocol)
			}
		}
	}

	if s.useTLS {
		return s.ListenAndServeTLS("", "")
	}
	return s.ListenAndServe()
}

// Stop the server.
func (s *ProxyServer) Stop(ctx context.Context) error {
	log.Info("proxy stopping")
	return s.Shutdown(ctx)
}

// 文件存在性检查函数
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func altSvcMiddleware(h http.Handler, h3Port string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 仅对HTTP/1.1和HTTP/2请求注入Alt-Svc
		if r.ProtoMajor < 3 && h3Port != "" {
			altValue := fmt.Sprintf(`h3=":%s"; ma=86400, h3-29=":%s"; ma=86400`, h3Port, h3Port)
			w.Header().Add("Alt-Svc", altValue)
		}
		h.ServeHTTP(w, r)
	})
}
