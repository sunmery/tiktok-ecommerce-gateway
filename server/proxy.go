package server

import (
	"context"
	"crypto/tls"
	"errors"
	"github.com/go-kratos/gateway/constants"
	"net/http"
	"os"
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
	useTLS bool // 新增字段，记录是否启用TLS
}

func NewProxy(handler http.Handler, addr string) *ProxyServer {
	useTLS := os.Getenv(constants.UseTLS) == "false" // 读取TLS环境变量

	var tlsConfig *tls.Config
	if useTLS {
		certFile := os.Getenv(constants.CrtFile)
		keyFile := os.Getenv(constants.KeyFile)

		if certFile == "" || keyFile == "" {
			log.Fatal("启用TLS时，certFile 或 keyFile 环境变量未设置")
		}

		// 检查证书文件是否存在
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

		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
	}

	return &ProxyServer{
		Server: &http.Server{
			Addr:              addr,
			TLSConfig:         tlsConfig,
			Handler:           handler,
			ReadTimeout:       readTimeout,
			ReadHeaderTimeout: readHeaderTimeout,
			WriteTimeout:      writeTimeout,
			IdleTimeout:       idleTimeout,
		},
		useTLS: useTLS, // 设置TLS启用状态
	}
}

func (s *ProxyServer) Start(ctx context.Context) error {
	log.Infof("proxy listening on %s (TLS: %v)", s.Addr, s.useTLS)
	var err error
	if s.useTLS {
		// 使用已加载的TLS配置
		err = s.ListenAndServeTLS("", "")
	} else {
		err = s.ListenAndServe()
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *ProxyServer) Stop(ctx context.Context) error {
	log.Info("proxy server stopping")
	return s.Server.Shutdown(ctx)
}

// 文件存在性检查
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}
