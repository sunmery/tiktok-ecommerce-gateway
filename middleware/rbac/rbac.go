package rbac

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/casbin/casbin/v2"
	redisadapter "github.com/casbin/redis-adapter/v3"
	config "github.com/go-kratos/gateway/api/gateway/config/v1"
	"github.com/go-kratos/gateway/middleware"
)

var (
	NotAuthZ             = errors.New("权限不足")
	syncedCachedEnforcer *casbin.SyncedCachedEnforcer
	cache                = NewCache(5*time.Minute, 10*time.Minute)
	casdoorUrl           = os.Getenv("casdoorUrl") // http://localhost:8000
	rbacModel            string                    // ./rbac_model.conf

	// userOwner        = os.Getenv("CASDOOR_ORG")
	userOwner         = "tiktok"
	userIdMetadataKey = "x-md-global-user-id"
)

// RoleType Casdoor角色字段
type RoleType struct {
	Owner       string        `json:"owner"`
	Name        string        `json:"name"`
	CreatedTime time.Time     `json:"createdTime"`
	DisplayName string        `json:"displayName"`
	Description string        `json:"description"`
	Users       interface{}   `json:"users"`
	Groups      []interface{} `json:"groups"`
	Roles       []interface{} `json:"roles"`
	Domains     []interface{} `json:"domains"`
	IsEnabled   bool          `json:"isEnabled"`
}

// 移除 init() 函数
var initialized bool

func InitEnforcer() {
	if initialized {
		return
	}
	redisAddr := os.Getenv("redisAddr") // localhost:6379
	if redisAddr == "" {
		panic("redisAddr 环境变量未设置")
	}

	middleware.Register("rbac", Middleware)
	initialized = true
	initEnforcer(redisAddr)
}

// 初始化策略
func initPolicies(e *casbin.SyncedCachedEnforcer) {
	policies := [][]string{
		// 公共接口 (不需要登录)
		{"public", "/v1/auth", "POST", "allow"},

		// 普通用户权限
		{"user", "/v1/auth/profile", "GET", "allow"},
		{"user", "/v1/products", "GET", "allow"},
		{"user", "/v1/users/*", "(GET|POST|PATCH|DELETE)", "allow"},
		{"user", "/v1/carts/*", "(GET|POST|DELETE)", "allow"},
		{"user", "/v1/checkout", "POST", "allow"},
		{"user", "/v1/orders", "(GET|POST)", "allow"},
		{"user", "/v1/categories/*", "GET", "allow"},

		// 商家特殊权限
		{"merchant", "/v1/products*", "(POST|PUT|DELETE)", "allow"},
		{"merchant", "/v1/products/*/submit-audit", "POST", "allow"},
		{"merchant", "/v1/categories", "POST", "allow"},
		{"merchant", "/v1/merchants", "(GET|POST|PUT|DELETE|PATCH)", "allow"},

		// 管理员专属权限
		{"admin", "/v1/categories/*", "(POST|PUT|DELETE|PATCH)", "allow"},
		{"admin", "/v1/products/*", "(GET|POST|PUT|DELETE|PATCH)", "allow"},
		{"admin", "/v1/products/*/audit", "POST", "allow"},
		{"admin", "/v1/merchants/*", "(GET|POST|PUT|DELETE|PATCH)", "allow"},
		{"admin", "/v1/order/*/paid", "POST", "allow"},

		// gRPC
		{"admin", "/ecommerce.product.v1.ProductService/*", "(POST|PUT|DELETE|PATCH)", "allow"},

		// 拒绝所有未明确允许的请求（默认拒绝）
		{"anyone", "/*", ".*", "deny"},
	}

	// 添加角色继承关系
	groupPolicies := [][]string{
		{"merchant", "user"},  // 商家继承普通用户
		{"admin", "merchant"}, // 管理员继承商家
	}

	// 添加普通策略
	for _, policy := range policies {
		if ok, _ := e.AddPolicy(policy); !ok {
			fmt.Printf("Policy %v already exists\n", policy)
		}
	}

	// 添加角色继承关系
	for _, policy := range groupPolicies {
		if ok, _ := e.AddGroupingPolicy(policy); !ok {
			fmt.Printf("Grouping policy %v already exists\n", policy)
		}
	}
}

// 初始化Casbin Enforcer
func initEnforcer(redisAddr string) {
	a, err := redisadapter.NewAdapter("tcp", redisAddr)
	if err != nil {
		panic(fmt.Errorf("failed to initialize redis adapter: %v", err))
	}

	rbacModel = os.Getenv("RBAC_MODEL")
	if rbacModel == "" {
		rbacModel = "./rbac_model.conf"
	}

	enforcer, err := casbin.NewSyncedCachedEnforcer(rbacModel, a)
	if err != nil {
		panic(fmt.Errorf("failed to initialize enforcer: %v", err))
	}
	syncedCachedEnforcer = enforcer

	// 初始化策略
	initPolicies(enforcer)
}

// Cache 结构（带线程安全）
type Cache struct {
	items    map[string]cacheItem
	mu       sync.RWMutex
	janitor  *cacheJanitor
	stopChan chan struct{}
}

type cacheItem struct {
	value      interface{}
	expiration int64
}

func NewCache(defaultExpiration, cleanupInterval time.Duration) *Cache {
	c := &Cache{
		items:    make(map[string]cacheItem),
		stopChan: make(chan struct{}),
	}

	janitor := &cacheJanitor{
		Interval: cleanupInterval,
		stop:     c.stopChan,
	}
	go janitor.Run(c)

	return c
}

func (c *Cache) Get(key string) (interface{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	item, exists := c.items[key]
	if !exists || time.Now().UnixNano() > item.expiration {
		return nil, false
	}
	return item.value, true
}

func (c *Cache) Set(key string, value interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items[key] = cacheItem{
		value:      value,
		expiration: time.Now().Add(5 * time.Minute).UnixNano(),
	}
}

type JwtOptions struct {
	SkipPaths []string `json:"skip_paths"`
}

// Middleware 中间件实现
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
			// 动态路由跳过检查
			if methods, ok := skipRules[req.URL.Path]; ok {
				if methods[req.Method] {
					return next.RoundTrip(req)
				}
			}

			// 1. 获取用户ID
			userID := req.Header.Get(userIdMetadataKey)
			if userID == "" {
				return nil, fmt.Errorf("%w: 缺少用户标识", NotAuthZ)
			}

			// 2. 获取用户角色
			role, err := getUserRoles(userID)
			if err != nil {
				return nil, fmt.Errorf("%w: 无法验证权限", err)
			}

			fmt.Printf("用户角色: %s\n", role)
			fmt.Printf("用户ID: %s\n", userID)
			// 3. 权限检查
			allowed, err := syncedCachedEnforcer.Enforce(role, req.URL.Path, req.Method)
			if err != nil {
				fmt.Printf("权限检查错误: role=%s path=%s method=%s error=%v\n",
					role, req.URL.Path, req.Method, err)

			}

			// 设置下游元数据
			if allowed {
				req.Header.Set("x-md-global-role", role)
				req.Header.Set("x-md-global-owner", userOwner)
				req.Header.Set("x-md-global-user-id", userID)
				return next.RoundTrip(req)
			}

			return nil, fmt.Errorf("%w: 角色%v无%s %s权限",
				NotAuthZ, role, req.Method, req.URL.Path)
		})
	}, nil
}

// 获取用户角色（带缓存）
func getUserRoles(userID string) (string, error) {
	// 检查缓存
	if cached, found := cache.Get(userID); found {
		return cached.(string), nil
	}

	// 调用Casdoor API
	role, err := fetchRolesFromCasdoor(userID)
	if err != nil {
		return "", err
	}

	// 更新缓存
	cache.Set(userID, role)
	return role, nil
}

// Casdoor角色查询
func fetchRolesFromCasdoor(userID string) (string, error) {
	id := fmt.Sprintf("%s/%s", userOwner, userID)
	// id = "tiktok/7ae63d43-493f-44b0-830e-6bf4064226a3"

	req, _ := http.NewRequest("GET", fmt.Sprintf("%s/api/get-user?id=%s&owner=%s", casdoorUrl, id, userOwner), nil)
	q := req.URL.Query()
	q.Add("owner", userOwner)
	h := req.Header
	h.Add("Content-Type", "application/json")

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("casdoor接口调用失败: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Data struct {
			Id    string     `json:"id"`
			Roles []RoleType `json:"roles"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("响应解析失败: %w", err)
	}

	var role string
	if userID == result.Data.Id {
		for _, u := range result.Data.Roles {
			role = u.Name
			break
		}
	}
	if role == "" {
		return "", fmt.Errorf("用户未分配角色")
	}
	return role, nil
}

type cacheJanitor struct {
	Interval time.Duration
	stop     chan struct{}
}

func (j *cacheJanitor) Run(c *Cache) {
	ticker := time.NewTicker(j.Interval)
	for {
		select {
		case <-ticker.C:
			c.cleanup()
		case <-j.stop:
			ticker.Stop()
			return
		}
	}
}

func (c *Cache) cleanup() {
	now := time.Now().UnixNano()
	for k, v := range c.items {
		if now > v.expiration {
			delete(c.items, k)
		}
	}
}
