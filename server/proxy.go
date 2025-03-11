package server

import (
	"context"
	"crypto/tls"
	"errors"
	"github.com/go-kratos/gateway/constants"
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
	useTLS bool
}

// NewProxy new a gateway server.
func NewProxy(handler http.Handler, addr string) *ProxyServer {
	useTLS := os.Getenv(constants.UseTLS) == "true"
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
		useTLS: useTLS,
	}
}

// Start the server.
func (s *ProxyServer) Start(ctx context.Context) error {
	log.Infof("proxy listening on %s", s.Addr)
	var err error
	if s.useTLS {
		// 证书已在 TLSConfig 中加载, 参数留空即可
		err = s.ListenAndServeTLS("", "")
	} else {
		err = s.ListenAndServe()
	}
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
