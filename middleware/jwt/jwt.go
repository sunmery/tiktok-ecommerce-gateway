package jwt

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	config "github.com/go-kratos/gateway/api/gateway/config/v1"
	"github.com/go-kratos/gateway/constants"
	"github.com/go-kratos/gateway/middleware"
	"github.com/go-kratos/gateway/pkg/loader" // 新增 loader 包
	"github.com/go-kratos/gateway/proxy/auth"
	"github.com/go-kratos/kratos/v2/log"
	"github.com/golang-jwt/jwt/v5"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	consulPrefix = "ecommerce/gateway" // 与 RBAC 保持一致的 Consul 前缀
)

var (
	NotAuthN          = errors.New("unauthorized: authentication required")
	publicKey         *rsa.PublicKey
	publicKeyLoader   *loader.ConsulFileLoader // 新增 Consul 加载器
	publicKeyPath     string
	keyReloadInterval = 5 * time.Second // 公钥重载间隔
	initialized       bool
	mu                sync.RWMutex // 公钥更新锁
)

func Init() {
	if initialized {
		return
	}

	// 初始化 Consul 加载器
	initConsulLoader()

	// 设置默认路径
	publicKeyPath = getPublicKeyPath()
	if err := ensureSecretsDir(); err != nil {
		panic(fmt.Sprintf("创建密钥目录失败: %v", err))
	}

	// 首次同步公钥
	if err := syncPublicKey(); err != nil {
		panic(fmt.Sprintf("初始化公钥失败: %v", err))
	}

	middleware.Register("jwt", Middleware)
	initialized = true

	// 启动定时检查
	go watchPublicKeyChanges()
}

func initConsulLoader() {
	consulAddr := strings.TrimPrefix(os.Getenv(constants.DiscoveryDsn), "consul://")
	var err error
	publicKeyLoader, err = loader.NewConsulFileLoader(consulAddr, consulPrefix)
	if err != nil {
		panic(fmt.Sprintf("创建Consul文件加载器失败: %v", err))
	}
}

func getPublicKeyPath() string {
	if path := os.Getenv(constants.JwtPubkeyPath); path != "" {
		return path
	}
	// 动态配置目录 + secrets/public.pem
	return filepath.Join(
		constants.ConfigDir,
		constants.SecretsDirName,
		constants.JwtPublicFileName,
	)
}

func ensureSecretsDir() error {
	fullPath := filepath.Dir(publicKeyPath)
	log.Infof("创建密钥目录: %s", fullPath)
	return os.MkdirAll(fullPath, 0755)
}

func syncPublicKey() error {
	// 从 Consul 下载到本地路径
	remoteKeyPath := filepath.Join(constants.SecretsDirName, constants.JwtPublicFileName)
	if err := publicKeyLoader.DownloadFile(remoteKeyPath, publicKeyPath); err != nil {
		return fmt.Errorf("下载公钥失败: %w (远程路径: %s)", err, remoteKeyPath)
	}

	// 重载公钥
	return reloadPublicKey()
}

func reloadPublicKey() error {
	certData, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return fmt.Errorf("读取证书文件失败: %v (路径: %s)", err, publicKeyPath)
	}

	block, _ := pem.Decode(certData)
	if block == nil {
		return errors.New("PEM 解码失败")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("解析证书失败: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	var ok bool
	if publicKey, ok = cert.PublicKey.(*rsa.PublicKey); !ok {
		return errors.New("非 RSA 公钥")
	}
	return nil
}

func watchPublicKeyChanges() {
	ticker := time.NewTicker(keyReloadInterval)
	defer ticker.Stop()

	for range ticker.C {
		tempFile := publicKeyPath + ".tmp"
		defer os.Remove(tempFile)

		// 下载最新公钥到临时文件
		remoteKeyPath := path.Join(constants.SecretsDirName, constants.JwtPublicFileName)
		log.Infof("远程公钥路径: %s", remoteKeyPath) // 添加调试日志
		if err := publicKeyLoader.DownloadFile(remoteKeyPath, tempFile); err != nil {
			log.Errorf("公钥更新检查失败: %v (远程路径: %s)", err, remoteKeyPath)
			continue
		}

		// 对比内容
		current, _ := os.ReadFile(publicKeyPath)
		newContent, _ := os.ReadFile(tempFile)
		if string(current) != string(newContent) {
			log.Info("检测到公钥变更，重新加载")
			if err := os.WriteFile(publicKeyPath, newContent, 0644); err != nil {
				log.Errorf("写入新公钥失败: %v", err)
				continue
			}
			if err := reloadPublicKey(); err != nil {
				log.Errorf("重载公钥失败: %v", err)
			}
			log.Info("公钥重载成功")
		}
	}
}

type CustomClaims struct {
	auth.User
}

func ParseJwt(tokenString string) (*CustomClaims, error) {
	mu.RLock()
	defer mu.RUnlock()

	t, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		if token.Method != jwt.SigningMethodRS256 {
			return nil, fmt.Errorf("不支持的签名方法: %v", token.Method.Alg())
		}
		return publicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("令牌解析失败: %w", err)
	}

	if claims, ok := t.Claims.(*CustomClaims); ok && t.Valid {
		return claims, nil
	}
	return nil, errors.New("无效的令牌声明")
}

func Middleware(c *config.Middleware) (middleware.Middleware, error) {
	var routerFilter *config.Middleware_RouterFilter
	if c != nil && c.RouterFilter != nil {
		routerFilter = c.RouterFilter
	} else {
		routerFilter = &config.Middleware_RouterFilter{} // 空配置
	}

	skipRules := make(map[string]map[string]bool)
	for _, rule := range routerFilter.Rules { // 安全访问
		methods := make(map[string]bool)
		for _, m := range rule.Methods {
			methods[strings.ToUpper(m)] = true
		}
		skipRules[rule.Path] = methods
	}
	return func(next http.RoundTripper) http.RoundTripper {
		return middleware.RoundTripperFunc(func(req *http.Request) (*http.Response, error) {
			log.Infof("Processing request: %s %s", req.Method, req.URL.Path)

			// 动态路由跳过检查
			if methods, ok := skipRules[req.URL.Path]; ok {
				if methods[req.Method] {
					return next.RoundTrip(req)
				}
			}

			authHeader := req.Header.Get("Authorization")
			if !strings.HasPrefix(authHeader, "Bearer ") {
				return nil, fmt.Errorf("%w: 缺失 Bearer 令牌", NotAuthN)
			}

			token := strings.TrimPrefix(authHeader, "Bearer ")
			claims, err := ParseJwt(token)
			if err != nil {
				log.Errorf("JWT 解析错误: %v", err)
				return nil, fmt.Errorf("%w: %v", NotAuthN, err)
			}

			// 传递到下游服务
			req.Header.Set("x-md-global-user-id", claims.ID)
			req.Header.Set("x-md-global-user-owner", claims.Owner)

			return next.RoundTrip(req)
		})
	}, nil
}
