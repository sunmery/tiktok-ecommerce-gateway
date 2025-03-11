package jwt

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"

	config "github.com/go-kratos/gateway/api/gateway/config/v1"
	"github.com/go-kratos/gateway/constants"
	"github.com/go-kratos/gateway/middleware"
	"github.com/go-kratos/gateway/pkg/loader"
	"github.com/go-kratos/gateway/proxy/auth"
	"github.com/go-kratos/kratos/v2/log"
	"github.com/golang-jwt/jwt/v5"
)

var (
	NotAuthN      = errors.New("unauthorized: authentication required")
	publicKey     *rsa.PublicKey
	publicKeyPath string
	initialized   bool
	mu            sync.RWMutex
)

func Init() error {
	if initialized {
		return nil
	}

	// 初始化公钥路径
	publicKeyPath = getPublicKeyPath()

	// 创建密钥目录
	if err := os.MkdirAll(filepath.Dir(publicKeyPath), 0o755); err != nil {
		return fmt.Errorf("创建密钥目录失败: %w", err)
	}

	// 获取Loader实例
	load, err := loader.GetConsulLoader()
	if err != nil {
		return fmt.Errorf("获取Loader失败: %w", err)
	}

	// 同步公钥文件
	if err := load.SyncFile(
		path.Join(constants.SecretsDirName, constants.JwtPublicFileName),
		publicKeyPath,
		validatePublicKey,
	); err != nil {
		return fmt.Errorf("公钥同步失败: %w", err)
	}

	// 初始加载公钥
	if err := reloadPublicKey(); err != nil {
		return fmt.Errorf("初始公钥加载失败: %w", err)
	}

	// 启动监听
	if err := load.Watch(
		path.Join(constants.SecretsDirName, constants.JwtPublicFileName),
		onPublicKeyUpdate,
	); err != nil {
		return fmt.Errorf("启动监听失败: %w", err)
	}

	middleware.Register("jwt", Middleware)
	initialized = true
	log.Info("[JWT] 初始化完成")
	return nil
}

func getPublicKeyPath() string {
	if pubPath := os.Getenv(constants.JwtPubkeyPath); pubPath != "" {
		return filepath.Clean(pubPath) // 防止路径注入
	}
	return filepath.Join(
		constants.ConfigDir,
		constants.SecretsDirName,
		constants.JwtPublicFileName,
	)
}

func onPublicKeyUpdate() {
	log.Info("[JWT] 检测到公钥变更，开始处理...")
	defer log.Info("[JWT] 更新处理完成")

	load, err := loader.GetConsulLoader()
	if err != nil {
		log.Errorf("[JWT] 获取加载器失败: %v", err)
		return
	}

	// 重新同步最新公钥文件
	if err := load.SyncFile(
		path.Join(constants.SecretsDirName, constants.JwtPublicFileName),
		publicKeyPath,
		validatePublicKey,
	); err != nil {
		log.Errorf("[JWT] 公钥同步失败: %v", err)
		return
	}

	// 重新加载公钥
	if err := reloadPublicKey(); err != nil {
		log.Errorf("[JWT] 公钥重载失败: %v", err)
	}
}

func reloadPublicKey() error {
	mu.Lock()
	defer mu.Unlock()

	// 检查文件是否最新
	_, err := os.Stat(publicKeyPath)
	if err != nil {
		return log.Errorf("文件状态获取失败: %w", err)
	}

	data, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return fmt.Errorf("读取文件失败: %w", err)
	}

	// 添加哈希校验
	newHash := fmt.Sprintf("%x", sha256.Sum256(data))
	if publicKey != nil {
		oldHash := fmt.Sprintf("%x", sha256.Sum256(publicKey.N.Bytes()))
		if newHash == oldHash {
			log.Warn("[JWT] 公钥未发生实际变更")
			return nil
		}
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
	log.Infof("[JWT] 公钥已更新 (SHA256: %s)", newHash)
	return nil
}

func validatePublicKey(tempPath string) error {
	data, err := os.ReadFile(tempPath)
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
			if methods, ok := skipRules[req.URL.Path]; ok && methods[req.Method] {
				return next.RoundTrip(req)
			}

			authHeader := req.Header.Get("Authorization")
			if !strings.HasPrefix(authHeader, "Bearer ") {
				return nil, fmt.Errorf("%w: Bearer token required", NotAuthN)
			}

			claims, err := ParseJwt(strings.TrimPrefix(authHeader, "Bearer "))
			if err != nil {
				return nil, fmt.Errorf("%w: %v", NotAuthN, err)
			}

			req.Header.Set(constants.UserIdMetadataKey, claims.ID)
			req.Header.Set(constants.UserOwner, claims.Owner)
			return next.RoundTrip(req)
		})
	}, nil
}
