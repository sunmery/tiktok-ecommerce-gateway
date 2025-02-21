package rbac

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/casbin/casbin/v2"
	config "github.com/go-kratos/gateway/api/gateway/config/v1"
	"github.com/go-kratos/gateway/middleware"
)

var (
	NotAuthZ             = errors.New("权限不足")
	syncedCachedEnforcer *casbin.SyncedCachedEnforcer
	cache                = NewCache(5*time.Minute, 10*time.Minute) // 新增缓存
)

// Cache 新增缓存结构
type Cache struct {
	items    map[string]cacheItem
	janitor  *cacheJanitor
	stopChan chan struct{}
}

type cacheItem struct {
	value      interface{}
	expiration int64
}

// 新增配置参数（建议从环境变量读取）
var (
	casdoorAPI = os.Getenv("CASDOOR_ADDR") // http://casdoor.com:8000
	// casdoorOwner = os.Getenv("CASDOOR_OWNER") // owner
	casdoorOwner = "tiktok" // owner

	// 需要传递的 metadata:
	// userIdMetadataKey = os.Getenv("USER_ID_METADATA_KEY") // x-md-global-user-id
	userIdMetadataKey = "x-md-global-user-id"
)

type RBAC struct {
	enforcer *casbin.SyncedCachedEnforcer
	// logger   log.Logger
}

func (r *RBAC) Middleware(c *config.Middleware) (middleware.Middleware, error) {
	return func(next http.RoundTripper) http.RoundTripper {
		return middleware.RoundTripperFunc(func(req *http.Request) (*http.Response, error) {
			// 跳过认证接口
			if req.URL.Path == "/v1/auth" && req.Method == http.MethodPost {
				return next.RoundTrip(req)
			}

			// 1. 从Header获取用户ID
			userID := req.Header.Get(userIdMetadataKey)
			if userID == "" {
				return nil, fmt.Errorf("%w: 缺少用户标识", NotAuthZ)
			}

			// 2. 获取用户角色（带缓存）
			roles, err := r.getUserRoles(userID)
			if err != nil {
				// r.logger.Errorf("获取角色失败: user=%s error=%v", userID, err)
				return nil, fmt.Errorf("%w: 无法验证权限", NotAuthZ)
			}

			// 3. 执行权限检查
			for _, role := range roles {
				allowed, err := r.enforcer.Enforce(role, req.URL.Path, req.Method)
				if err != nil {
					// r.logger.Warnf("权限检查错误: role=%s path=%s method=%s error=%v",
					// 	role, req.URL.Path, req.Method, err)
					fmt.Printf("权限检查错误: role=%s path=%s method=%s error=%v",
						role, req.URL.Path, req.Method, err)
					continue
				}

				if allowed {
					// 传递角色到上下文
					ctx := context.WithValue(req.Context(), "current_roles", roles)
					return next.RoundTrip(req.WithContext(ctx))
				}
			}

			return nil, fmt.Errorf("%w: 角色%v无%s %s权限",
				NotAuthZ, roles, req.Method, req.URL.Path)
		})
	}, nil
}

// 新增：带缓存的角色获取方法
func (r *RBAC) getUserRoles(userID string) ([]string, error) {
	// 检查缓存
	if cached, found := cache.Get(userID); found {
		return cached.([]string), nil
	}

	// 调用Casdoor API
	roles, err := fetchRolesFromCasdoor(userID)
	if err != nil {
		return nil, err
	}

	// 更新缓存
	cache.Set(userID, roles)
	return roles, nil
}

// 新增：Casdoor接口调用逻辑
func fetchRolesFromCasdoor(userID string) ([]string, error) {
	// 构造请求
	req, _ := http.NewRequest("GET", fmt.Sprintf("%s/api/get-roles", casdoorAPI), nil)
	q := req.URL.Query()
	q.Add("owner", casdoorOwner)
	req.URL.RawQuery = q.Encode()

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("casdoor接口调用失败: %w", err)
	}
	defer resp.Body.Close()

	// 解析响应
	var result struct {
		Data []struct {
			Name  string   `json:"name"`
			Users []string `json:"users"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("响应解析失败: %w", err)
	}

	// 匹配用户角色
	var roles []string
	for _, group := range result.Data {
		for _, u := range group.Users {
			if u == userID {
				roles = append(roles, group.Name)
				break
			}
		}
	}

	if len(roles) == 0 {
		return nil, fmt.Errorf("用户未分配角色")
	}
	return roles, nil
}

// NewCache 新增缓存实现
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
	item, exists := c.items[key]
	if !exists || time.Now().UnixNano() > item.expiration {
		return nil, false
	}
	return item.value, true
}

func (c *Cache) Set(key string, value interface{}) {
	c.items[key] = cacheItem{
		value:      value,
		expiration: time.Now().Add(5 * time.Minute).UnixNano(),
	}
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
