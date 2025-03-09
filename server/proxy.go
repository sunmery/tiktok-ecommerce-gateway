package server

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"time"

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
	if v := os.Getenv("PROXY_READ_HEADER_TIMEOUT"); v != "" {
		if readHeaderTimeout, err = time.ParseDuration(v); err != nil {
			panic(err)
		}
	}
	if v := os.Getenv("PROXY_READ_TIMEOUT"); v != "" {
		if readTimeout, err = time.ParseDuration(v); err != nil {
			panic(err)
		}
	}
	if v := os.Getenv("PROXY_WRITE_TIMEOUT"); v != "" {
		if writeTimeout, err = time.ParseDuration(v); err != nil {
			panic(err)
		}
	}
	if v := os.Getenv("PROXY_IDLE_TIMEOUT"); v != "" {
		if idleTimeout, err = time.ParseDuration(v); err != nil {
			panic(err)
		}
	}
}

// ProxyServer is a proxy server.
type ProxyServer struct {
	*http.Server
}

// NewProxy new a gateway server.
func NewProxy(handler http.Handler, addr string) *ProxyServer {
	// TLS
	certFile := os.Getenv("certFile")
	keyFile := os.Getenv("keyFile")

	// 获取当前工作目录
	wd, _ := os.Getwd()
	log.Infof("当前工作目录: %s", wd)
	log.Infof("certFile绝对路径: %s", filepath.Join(wd, certFile))
	log.Infof("keyFile绝对路径: %s", filepath.Join(wd, keyFile))

	if certFile == "" || keyFile == "" {
		log.Fatal("certFile 或 keyFile 环境变量未设置")
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
	return &ProxyServer{
		Server: &http.Server{
			Addr: addr,
			TLSConfig: &tls.Config{
				Certificates: []tls.Certificate{cert}, // 添加证书
				MinVersion:   tls.VersionTLS12,        //  // 设置最低支持的 TLS 版本
			},
			// TLS HTTP/2 标准加密传输协议
			Handler: handler,

			// 明文 HTTP/2
			// Handler: h2c.NewHandler(handler, &http2.Server{
			// 	IdleTimeout:          idleTimeout,
			// 	MaxConcurrentStreams: math.MaxUint32,
			// }),

			ReadTimeout:       readTimeout,
			ReadHeaderTimeout: readHeaderTimeout,
			WriteTimeout:      writeTimeout,
			IdleTimeout:       idleTimeout,
		},
	}
}

// Start the server.
func (s *ProxyServer) Start(ctx context.Context) error {
	log.Infof("proxy listening on %s", s.Addr)
	// HTTP
	// err := s.ListenAndServe()

	// TLS
	// 证书已在 TLSConfig 中加载, 参数留空即可
	err := s.ListenAndServeTLS("", "")
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
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
