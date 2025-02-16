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
	"strings"
)

var (
	NotAuthN = errors.New("unauthorized: authentication required")
	certPEM  = `-----BEGIN CERTIFICATE-----
MIIE2TCCAsGgAwIBAgIDAeJAMA0GCSqGSIb3DQEBCwUAMCYxDjAMBgNVBAoTBWFk
bWluMRQwEgYDVQQDDAtjZXJ0X2dteTlhbzAeFw0yNTAyMDcxOTIyMTNaFw00NTAy
MDcxOTIyMTNaMCYxDjAMBgNVBAoTBWFkbWluMRQwEgYDVQQDDAtjZXJ0X2dteTlh
bzCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBANi0KGG7OMu+GU33kZDi
7q9+8d78/ibCXiHsUXgA7RfDCh4Tw3YMWSA/CmYYvZdL2zfOIg5v+i8KINDGPCRo
xpeVbOPhHogrFV2osaMv9pucDtzlqgddvId3LwT567AUPfP0I+xvJygSuuYLHIoA
tmmugbdsiNA0TwaenP12EmBaMpEiMwf0f570+sb0ZqBerM7ksmSZC7eb8qq4QXbb
+yJCpNDXmYXk73CzzVumqHh2yBQxcKHfs+WFeuwHwfqDjPE5v6V2kInnU0Kr0N7/
mgbsM60QOtCd1M6uS1Cude5H/G76j7X0PLRQ3gquuAN85IZmrAx3sDPyxjB/t5OQ
JCMShfvS+R7ffgtfbU9uMHYAxDBBO7UPh4iG944RD6ur3jqZHjTSSABF54mT2M0K
Ly8X3eRLO8H3MT1BuNRFZiIqAyqk64HuSqRfKnY1DUR54bbDOhDnYxDFhZAWwewu
4jRh56HOePVvKC6S9/P1etOf8vleKJmdwSmhjkXsgWieSGR8jy8udNxcpaFXEA2r
1OnuQDd3QQiQAvTHP0cKFx33WG7ja4bYzRX096WmxutFDhodQR46X1107dkZUt/I
TxGoBx/DWeiW0lNue4E02hieMkPcKx9X8MHlzj6p5PPad3rWVnmPlB5rVXE4Z89E
2Ps022NnNR8r+ZJGEo2DevGvAgMBAAGjEDAOMAwGA1UdEwEB/wQCMAAwDQYJKoZI
hvcNAQELBQADggIBAJoMGpaCLLd+GaenKkY3mRNCS+zr3TCUy0rwgzs0W5Bo9tQm
tgxcYTR5r4QpKd+qc8rGFeepUJFAEfcdmN+0r+k4cVgnJykgZrE/fR96kCuKMmU7
46HXYM3TTE0+WO+own1NbmRqgAYuIF5kGbDcKlGZoHW5bHOdRMb/Wj8N4gwpD0P/
E4C7FjwaDPBYpgAs8NMtxwCKJCxRsay9iYBT6lufOwbv4KLoLc2NgtT9AHQCgU9O
ri+cwsJJR7nAAKcmnTvhQvBzbo3iMXCcfUxH/Qyia35JP4NbK2zrEPVlp5vWTYqn
9RoWX+s/+kKjWKh86sYHXbQCIw6+yuAaFjw1ylDa59izRgwKPETlbsEcLIVivyqM
IqxhSNGUjaj3KUPjDvdamAWwBQHS2u5FBGGIOn6Dq7e/mxiI4o+8b8Hvj6fdsv8G
ZwKNXI+TUWKJX14lD6P/NPrWyZYzEtBu1dlGeskhvg1yoasqBrd5m05R7zivm4JQ
2G8LaOhGusiq9KLl0KlWbxNuiUC97CZRAewGO3CKnB5WJL45NRiMm8GzuMCGsrBL
1YbIuSiBwkZRDYx0mUfNvIz6md2VTwjP0V5y/1ls2avf4tWSz1F0w4YZLhJF+uSe
I27BpK+gU6NkYWr5BxYg2P7phgKPBBrJJi2+CgGmZBZsjWwm8IeW7H22n8PP
-----END CERTIFICATE-----`
)

func init() {
	middleware.Register("jwt", Middleware)
}

func ParseJwt(tokenString string, publicKey *rsa.PublicKey) (*auth.User, error) {
	t, err := jwt.ParseWithClaims(tokenString, &auth.User{}, func(token *jwt.Token) (interface{}, error) {
		if token.Method != jwt.SigningMethodRS256 {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Method.Alg())
		}
		return publicKey, nil
	})
	if err != nil {
		return nil, err
	}
	if !t.Valid {
		return nil, errors.New("invalid token")
	}
	claims, ok := t.Claims.(*auth.User)
	if !ok {
		return nil, errors.New("invalid token claims type")
	}
	return claims, nil
}

func Middleware(c *config.Middleware) (middleware.Middleware, error) {
	// 解析证书获取公钥
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, errors.New("failed to decode certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}
	publicKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("certificate public key is not RSA")
	}

	return func(next http.RoundTripper) http.RoundTripper {
		return middleware.RoundTripperFunc(func(req *http.Request) (*http.Response, error) {
			authHeader := req.Header.Get("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				parts := strings.SplitN(authHeader, " ", 2)
				if len(parts) != 2 {
					return nil, errors.Join(NotAuthN, errors.New("invalid authorization header format"))
				}

				token := parts[1]
				user, err := ParseJwt(token, publicKey)

				if err != nil {
					log.Errorf("JWT parse error: %v", err)
					return nil, errors.Join(NotAuthN, err)
				}

				reqOpt, ok := middleware.FromRequestContext(req.Context())
				if !ok {
					return nil, errors.Join(NotAuthN, errors.New("no request context found"))
				}
				reqOpt.Values.Set("user", user)
				reqOpt.Values.Set("x-md-global-userid", user.ID)
				reqOpt.Values.Set("x-md-global-owner", user.Owner)
				reqOpt.Values.Set("x-md-global-name", user.Name)

				// HTTP 传递 header 参数到下游微服务
				req.Header.Set("x-md-global-userid", user.ID)
				req.Header.Set("x-md-global-owner", user.Owner)
				req.Header.Set("x-md-global-name", user.Name)

				// debug
				fmt.Printf("user%+v\n", user)
				id, ok := reqOpt.Values.Get("x-md-global-userid")
				if !ok {
					return nil, errors.Join(NotAuthN, errors.New("no user id found"))
				}
				fmt.Printf("id: %+v\n", id)
				// debug

				return next.RoundTrip(req)
			}
			return nil, errors.Join(NotAuthN, errors.New("missing bearer token"))
		})
	}, nil
}
