package auth

import (
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strings"

	"github.com/go-kratos/gateway/router/mux"
	"github.com/go-kratos/kratos/v2/log"
	"github.com/golang-jwt/jwt/v5"
)

var (
	_prefix = "/auth"
	service = &authService{
		handlers: make(map[string]http.HandlerFunc),
	}
)

func Registry(path string, h http.HandlerFunc) {
	service.handlers[_prefix+path] = h
}

type authService struct {
	handlers map[string]http.HandlerFunc
}

func (service *authService) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	defer func() {
		if err := recover(); err != nil {
			http.Error(w, "系统异常", http.StatusInternalServerError)
			buf := make([]byte, 64<<10) //nolint:gomnd
			n := runtime.Stack(buf, false)
			log.Errorf("panic recovered: %+v\n%s", err, buf[:n])
			fmt.Fprintf(os.Stderr, "panic recovered: %+v\n%s\n", err, buf[:n])
		}
	}()
	service.handlers[req.URL.Path](w, req)
}

func Handler(origin http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if strings.HasPrefix(req.URL.Path, _prefix) {
			mux.ProtectedHandler(service).ServeHTTP(w, req)
			return
		}
		origin.ServeHTTP(w, req)
	})
}

type User struct {
	Owner                string // 用户所在的组织
	SignupApplication    string // 用户所在的应用
	Name                 string // 用户姓名
	ID                   string // 用户唯一标识
	Email                string // 用户邮箱
	Avatar               string // 用户头像 string
	IsDeleted            bool   // 用户是否注销 bool
	CreatedTime          string // time.Time
	UpdatedTime          string // time.Time
	DeletedTime          string // time.Time
	DisplayName          string // 要显示的用户名
	jwt.RegisteredClaims        // v5版本新加的方法
}
