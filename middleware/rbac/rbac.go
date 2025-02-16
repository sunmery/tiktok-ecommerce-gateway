package rbac

import (
	"errors"
	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/mongodb-adapter/v3"
	config "github.com/go-kratos/gateway/api/gateway/config/v1"
	"github.com/go-kratos/gateway/middleware"
	"github.com/go-kratos/gateway/proxy/auth"
	"github.com/go-kratos/kratos/v2/log"
	"net/http"
)

var (
	NotAuthZ             = errors.New("权限不足")
	syncedCachedEnforcer *casbin.SyncedCachedEnforcer
	rbacModel            = `
		[request_definition]
		r = sub, obj, act
		
		[policy_definition]
		p = sub, obj, act
		
		[role_definition]
		g = _, _
		
		[policy_effect]
		e = some(where (p.eft == allow))
		
		[matchers]
		m = r.sub == p.sub && keyMatch2(r.obj,p.obj) && r.act == p.act
	`
)

func init() {
	// middleware.Register("rbac", Middleware)
	// initCasbinEnforcer()
}

func initCasbinEnforcer() {
	model, err := model.NewModelFromString(rbacModel)
	if err != nil {
		log.Fatalf("字符串%s加载模型失败!", rbacModel)
	}
	config := mongodbadapter.AdapterConfig{
		DatabaseName:   "yqy_sys",
		CollectionName: "casbin_rule",
		IsFiltered:     true,
		Timeout:        10,
	}
	a, err := mongodbadapter.NewAdapterByDB(auth.Db.Client(), &config)
	if err != nil {
		log.Fatalf("casbin mongodb adapter 创建失败，url is %v !", config)
	}
	syncedCachedEnforcer, _ = casbin.NewSyncedCachedEnforcer(model, a)
	syncedCachedEnforcer.SetExpireTime(60 * 60)

	syncedCachedEnforcer.AddPolicies([][]string{
		{"admin", "/helloworld/*", "read"},
	})
}

func Middleware(c *config.Middleware) (middleware.Middleware, error) {
	return func(next http.RoundTripper) http.RoundTripper {
		return middleware.RoundTripperFunc(func(req *http.Request) (resp *http.Response, err error) {
			method := req.Method
			path := req.URL.Path
			reqOpt, _ := middleware.FromRequestContext(req.Context())
			var authorityId string
			if user, ok := reqOpt.Values.Get("user"); ok {
				u, _ := user.(*auth.User)
				authorityId = u.Name
			} else {
				authorityId = "admin"
			}
			ok, err := syncedCachedEnforcer.Enforce(authorityId, path, method)
			if err != nil {
				return nil, errors.Join(NotAuthZ, err)
			}
			if !ok {
				return nil, NotAuthZ
			}
			return next.RoundTrip(req)
		})
	}, nil
}
