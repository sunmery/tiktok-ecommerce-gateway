package auth

import (
	"fmt"
	"github.com/go-kratos/gateway/router/mux"
	"github.com/go-kratos/kratos/v2/log"
	"github.com/golang-jwt/jwt/v5"
	"net/http"
	"os"
	"runtime"
	"strings"
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
	Owner                string
	Name                 string
	ID                   string
	Type                 string
	Email                string
	jwt.RegisteredClaims // v5版本新加的方法
}
