package jwt

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	config "github.com/go-kratos/gateway/api/gateway/config/v1"
	"github.com/go-kratos/gateway/middleware"
	"github.com/go-kratos/gateway/proxy/auth"
	"github.com/go-kratos/kratos/v2/log"
	"github.com/golang-jwt/jwt/v5"
	"net/http"
	"os"
	"strings"
)

var (
	NotAuthN      = errors.New("unauthorized: authentication required")
	publicKey     *rsa.PublicKey
	publicKeyPath =os.Getenv("JWT_PUBKEY_PATH") // 证书文件路径
)

func init() {
	middleware.Register("jwt", Middleware)
// 初始化时加载证书
	loadPublicKey()
}

func loadPublicKey() {
	certData, err := os.ReadFile(publicKeyPath)
	if err != nil {
		panic(fmt.Sprintf("读取证书文件失败: %v", err))
	}

	block, _ := pem.Decode(certData)
	if block == nil {
		panic("PEM 解码失败")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic(fmt.Sprintf("解析证书失败: %v", err))
	}

	var ok bool
	if publicKey, ok = cert.PublicKey.(*rsa.PublicKey); !ok {
		panic("非 RSA 公钥")
	}
}

type CustomClaims struct {
	auth.User
}

func ParseJwt(tokenString string) (*CustomClaims, error) {
	t, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		if token.Method != jwt.SigningMethodRS256 {
			return nil, fmt.Errorf("不支持的签名方法: %v", token.Method.Alg())
		}
		return publicKey, nil
	})

	if err != nil {
		return nil, errors.New("令牌解析失败")
	}

	if claims, ok := t.Claims.(*CustomClaims); ok && t.Valid {
		return claims, nil
	}
	return nil, errors.New("无效的令牌声明")
}

func Middleware(c *config.Middleware) (middleware.Middleware, error) {
	return func(next http.RoundTripper) http.RoundTripper {
		return middleware.RoundTripperFunc(func(req *http.Request) (*http.Response, error) {
			log.Infof("Processing request: %s %s", req.Method, req.URL.Path)

			// 跳过认证的路径
			if req.URL.Path == "/v1/auth" && req.Method == "POST" {
				return next.RoundTrip(req)
			}
			// TODO
			if req.URL.Path == "/v1/products" && req.Method == "GET" {
				return next.RoundTrip(req)
			}
			if req.URL.Path == "/v1/payments/notify" && req.Method == "POST" {
				return next.RoundTrip(req)
			}
			if req.URL.Path == "/v1/payments/callback" && req.Method == "POST" {
				return next.RoundTrip(req)
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
