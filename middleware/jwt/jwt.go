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
	"github.com/go-kratos/gateway/pkg/loader"
	"github.com/go-kratos/gateway/proxy/auth"
	"github.com/go-kratos/kratos/v2/log"
	"github.com/golang-jwt/jwt/v5"
	"github.com/hashicorp/consul/api"
	"github.com/hashicorp/consul/api/watch"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	consulPrefix = "ecommerce/gateway"
)

var (
	NotAuthN        = errors.New("unauthorized: authentication required")
	publicKey       *rsa.PublicKey
	publicKeyLoader *loader.ConsulFileLoader
	publicKeyPath   string
	initialized     bool
	mu              sync.RWMutex
)

func Init() error {
	if initialized {
		return nil
	}

	if err := initConsulLoader(); err != nil {
		return fmt.Errorf("consul 初始化失败: %w", err)
	}

	publicKeyPath = getPublicKeyPath()
	if err := initLocalFiles(); err != nil {
		return fmt.Errorf("文件初始化失败: %w", err)
	}

	if err := loadAndVerifyPublicKey(); err != nil {
		return fmt.Errorf("公钥初始化失败: %w", err)
	}

	middleware.Register("jwt", Middleware)
	initialized = true

	go startKeyWatcher()
	log.Info("[JWT] 初始化完成，开始监听公钥变更")
	return nil
}

func initConsulLoader() error {
	addr := strings.TrimPrefix(os.Getenv(constants.DiscoveryDsn), "consul://")
	newLoader, err := loader.NewConsulFileLoader(addr, consulPrefix)
	if err != nil {
		return fmt.Errorf("创建Consul加载器失败: %w", err)
	}
	publicKeyLoader = newLoader
	return nil
}

func initLocalFiles() error {
	secretsDir := filepath.Dir(publicKeyPath)
	if err := os.MkdirAll(secretsDir, 0755); err != nil {
		return fmt.Errorf("创建密钥目录失败: %w", err)
	}
	return syncPublicKey()
}

func getPublicKeyPath() string {
	if pubPath := os.Getenv(constants.JwtPubkeyPath); pubPath != "" {
		return pubPath
	}
	return filepath.Join(
		constants.ConfigDir,
		constants.SecretsDirName,
		constants.JwtPublicFileName,
	)
}

func startKeyWatcher() {
	watchPath := path.Join(constants.SecretsDirName, constants.JwtPublicFileName)
	startConsulWatch(watchPath, onPublicKeyUpdate)
}

func startConsulWatch(keyPath string, callback func()) {
	fullPath := path.Join(consulPrefix, keyPath)
	log.Infof("[JWT] 启动公钥监听: %s", fullPath)

	params := map[string]interface{}{
		"type": "key",
		"key":  fullPath,
	}

	watcher, err := watch.Parse(params)
	if err != nil {
		log.Errorf("[JWT] 创建监视器失败: %v", err)
		return
	}

	watcher.Handler = func(idx uint64, data interface{}) {
		if _, ok := data.(*api.KVPair); ok {
			log.Infof("[JWT] 检测到公钥变更: %s", fullPath)
			callback()
		}
	}

	for {
		if err := watcher.RunWithClientAndHclog(publicKeyLoader.Client, nil); err != nil {
			log.Errorf("[JWT] 监听错误: %v (5秒后重试)", err)
			time.Sleep(5 * time.Second)
		}
	}
}

func onPublicKeyUpdate() {
	log.Info("[JWT] 开始处理公钥更新...")
	defer log.Info("[JWT] 公钥更新处理完成")

	if err := syncPublicKey(); err != nil {
		log.Errorf("[JWT] 公钥同步失败: %v", err)
		return
	}

	if err := reloadPublicKey(); err != nil {
		log.Errorf("[JWT] 公钥重载失败: %v", err)
	}
}

func syncPublicKey() error {
	tempFile := publicKeyPath + ".tmp"
	defer os.Remove(tempFile)

	remotePath := path.Join(constants.SecretsDirName, constants.JwtPublicFileName)
	if err := publicKeyLoader.DownloadFile(remotePath, tempFile); err != nil {
		return fmt.Errorf("下载失败: %w", err)
	}

	if err := validatePublicKey(tempFile); err != nil {
		return fmt.Errorf("公钥校验失败: %w", err)
	}

	if err := atomicReplaceFile(tempFile, publicKeyPath); err != nil {
		return fmt.Errorf("文件替换失败: %w", err)
	}
	return nil
}
func reloadPublicKey() error {
	mu.Lock()
	defer mu.Unlock()

	data, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return fmt.Errorf("读取文件失败: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return errors.New("PEM 解码失败")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("证书解析失败: %w", err)
	}

	pubKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return errors.New("非 RSA 公钥类型")
	}
	publicKey = pubKey
	return nil
}
func validatePublicKey(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return errors.New("无效PEM格式")
	}

	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		return fmt.Errorf("证书解析失败: %w", err)
	}
	return nil
}

func atomicReplaceFile(src, dst string) error {
	if err := os.Rename(src, dst); err != nil {
		return fmt.Errorf("文件替换失败: %w", err)
	}
	log.Infof("[JWT] 成功更新文件: %s", dst)
	return nil
}

func loadAndVerifyPublicKey() error {
	mu.Lock()
	defer mu.Unlock()

	data, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return fmt.Errorf("读取文件失败: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return errors.New("PEM解码失败")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("证书解析失败: %w", err)
	}

	pubKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return errors.New("非RSA公钥类型")
	}

	publicKey = pubKey
	log.Info("[JWT] 公钥加载成功")
	return nil
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
	// 解析跳过规则
	skipRules := make(map[string]map[string]bool)
	if c.GetRouterFilter() != nil {
		for _, rule := range c.GetRouterFilter().Rules {
			methods := make(map[string]bool)
			for _, m := range rule.Methods {
				methods[strings.ToUpper(m)] = true
			}
			skipRules[rule.Path] = methods
		}
	}
	return func(next http.RoundTripper) http.RoundTripper {
		return middleware.RoundTripperFunc(func(req *http.Request) (*http.Response, error) {
			// 检查白名单
			if methods, ok := skipRules[req.URL.Path]; ok && methods[req.Method] {
				return next.RoundTrip(req)
			}

			// 提取令牌
			authHeader := req.Header.Get("Authorization")
			if !strings.HasPrefix(authHeader, "Bearer ") {
				return nil, fmt.Errorf("%w: Bearer token required", NotAuthN)
			}

			// 解析 JWT
			claims, err := ParseJwt(strings.TrimPrefix(authHeader, "Bearer "))
			if err != nil {
				return nil, fmt.Errorf("%w: %v", NotAuthN, err)
			}

			// 传递用户信息
			req.Header.Set(constants.UserIdMetadataKey, claims.ID)
			req.Header.Set(constants.UserOwner, claims.Owner)
			return next.RoundTrip(req)
		})
	}, nil
}
