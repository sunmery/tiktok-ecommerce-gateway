package rbac

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	fileadapter "github.com/casbin/casbin/v2/persist/file-adapter"
	config "github.com/go-kratos/gateway/api/gateway/config/v1"
	"github.com/go-kratos/gateway/constants"
	"github.com/go-kratos/gateway/middleware"
	"github.com/go-kratos/gateway/pkg/loader"
	"github.com/go-kratos/kratos/v2/log"
)

var (
	logger               = log.NewHelper(log.With(log.DefaultLogger, "module", "middleware/rbac"))
	NotAuthZ             = errors.New("权限不足")
	syncedCachedEnforcer *casbin.SyncedCachedEnforcer
	enforcerMutex        sync.RWMutex
	cache                = NewCache(5*time.Minute, 10*time.Minute)
	casdoorUrl           = os.Getenv(constants.CasdoorUrl)
	userOwner            = constants.UserOwner
	userIdMetadataKey    = constants.UserIdMetadataKey
	initialized          bool
	localPolicyFile      = os.Getenv(constants.PoliciesfilePath)
	localModelFile       = os.Getenv(constants.ModelFilePath)
)

// InitEnforcer 初始化RBAC系统
func InitEnforcer() error {
	if initialized {
		return nil
	}

	initPathsErr := initPaths()
	if initPathsErr != nil {
		return initPathsErr
	}

	load, err := loader.GetConsulLoader()
	if err != nil {
		logger.Errorf("获取Consul加载器失败: %v", err)
		return err
	}

	if err := syncEssentialFiles(load); err != nil {
		logger.Errorf("文件同步失败: %v", err)
		return err
	}

	if err := initializeEnforcer(); err != nil {
		logger.Errorf("执行器初始化失败: %v", err)
		return err
	}

	setupWatchers(load)
	middleware.Register("rbac", Middleware)
	initialized = true
	logger.Info("RBAC系统初始化完成")

	return err
}

func initPaths() error {
	if localModelFile == "" {
		localModelFile = filepath.Join(constants.ConfigDir, constants.RBACDirName, constants.ModelFileFileName)
	}
	if localPolicyFile == "" {
		localPolicyFile = filepath.Join(constants.ConfigDir, constants.RBACDirName, constants.PoliciesfileName)
	}
	logger.Debugf("策略文件路径: %s | 模型文件路径: %s", localPolicyFile, localModelFile)

	if err := os.MkdirAll(filepath.Dir(localPolicyFile), 0o755); err != nil {
		logger.Errorf("创建策略目录失败: %v", err)
		return err
	}
	return nil
}

func syncEssentialFiles(load *loader.ConsulFileLoader) error {
	logger.Info("开始同步策略文件...")
	defer logger.Debugf("文件同步完成")

	if err := load.SyncFile(
		path.Join(constants.RBACDirName, constants.PoliciesfileName),
		localPolicyFile,
		validateFileContent,
	); err != nil {
		return err
	}

	return load.SyncFile(
		path.Join(constants.RBACDirName, constants.ModelFileFileName),
		localModelFile,
		validateFileContent,
	)
}

func validateFileContent(path string) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("读取文件失败: %w", err)
	}

	if len(content) == 0 {
		logger.Warnf("检测到空文件: %s", path)
		return errors.New("空文件")
	}

	logger.Debugf("文件验证通过: %s (大小: %d字节)", path, len(content))
	return nil
}

func initializeEnforcer() error {
	// 记录文件哈希
	fileHash := func(path string) string {
		data, _ := os.ReadFile(path)
		return fmt.Sprintf("%x", sha256.Sum256(data))
	}

	logger.Debugf("加载模型文件: %s (SHA256: %s)",
		localModelFile,
		fileHash(localModelFile),
	)

	modelContent, err := os.ReadFile(localModelFile)
	if err != nil {
		return fmt.Errorf("读取模型文件失败: %w", err)
	}

	m, err := model.NewModelFromString(string(modelContent))
	if err != nil {
		return fmt.Errorf("创建模型失败: %w", err)
	}

	adapter := fileadapter.NewAdapter(localPolicyFile)
	enforcer, err := casbin.NewSyncedCachedEnforcer(m, adapter)
	if err != nil {
		return fmt.Errorf("创建执行器失败: %w", err)
	}

	enforcerMutex.Lock()
	defer enforcerMutex.Unlock()
	syncedCachedEnforcer = enforcer
	syncedCachedEnforcer.StartAutoLoadPolicy(1 * time.Minute)
	return nil
}

func setupWatchers(load *loader.ConsulFileLoader) {
	watchPaths := []struct {
		path     string
		callback func()
	}{
		{path.Join(constants.RBACDirName, constants.PoliciesfileName), onPolicyUpdate},
		{path.Join(constants.RBACDirName, constants.ModelFileFileName), onModelUpdate},
	}

	for _, w := range watchPaths {
		if err := load.Watch(w.path, w.callback); err != nil {
			logger.Errorf("启动监听失败: %s: %v", w.path, err)
		}
	}
}

func onPolicyUpdate() {
	logger.Info("检测到策略变更，开始处理...")
	defer logger.Info("策略更新处理完成")

	load, err := loader.GetConsulLoader()
	if err != nil {
		logger.Error(err)
		return
	}

	if err := load.SyncFile(
		path.Join(constants.RBACDirName, constants.PoliciesfileName),
		localPolicyFile,
		validateFileContent,
	); err != nil {
		logger.Errorf("策略文件同步失败: %v", err)
		return
	}

	enforcerMutex.RLock()
	defer enforcerMutex.RUnlock()
	if err := syncedCachedEnforcer.LoadPolicy(); err != nil {
		logger.Errorf("策略重载失败: %v", err)
	}
}

func onModelUpdate() {
	logger.Info("检测到模型变更，开始处理...")
	defer logger.Info("模型更新处理完成")

	// 新增文件同步逻辑
	load, err := loader.GetConsulLoader()
	if err != nil {
		logger.Errorf("获取加载器失败: %v", err)
		return
	}

	if err := load.SyncFile(
		path.Join(constants.RBACDirName, constants.ModelFileFileName),
		localModelFile,
		validateFileContent,
	); err != nil {
		logger.Errorf("模型文件同步失败: %v", err)
		return
	}

	// 重新初始化执行器
	if err := initializeEnforcer(); err != nil {
		logger.Errorf("模型重载失败: %v", err)
	}
}

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

func NewCache(_, cleanupInterval time.Duration) *Cache {
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

func Middleware(c *config.Middleware) (middleware.Middleware, error) {
	var routerFilter *config.Middleware_RouterFilter
	if c != nil && c.RouterFilter != nil {
		routerFilter = c.RouterFilter
	} else {
		routerFilter = &config.Middleware_RouterFilter{}
	}

	skipRules := make(map[string]map[string]bool)
	for _, rule := range routerFilter.Rules {
		methods := make(map[string]bool)
		for _, m := range rule.Methods {
			methods[strings.ToUpper(m)] = true
		}
		skipRules[rule.Path] = methods
	}
	return func(next http.RoundTripper) http.RoundTripper {
		return middleware.RoundTripperFunc(func(req *http.Request) (*http.Response, error) {
			if methods, ok := skipRules[req.URL.Path]; ok {
				if methods[req.Method] {
					return next.RoundTrip(req)
				}
			}

			userID := req.Header.Get(userIdMetadataKey)
			if userID == "" {
				return nil, fmt.Errorf("%w: 缺少用户标识", NotAuthZ)
			}

			role, err := getUserRoles(userID)
			if err != nil {
				return nil, fmt.Errorf("%w: 无法验证权限", err)
			}

			fmt.Println("role, req.URL.Path, req.Method", role, req.URL.Path, req.Method)
			enforcerMutex.RLock()
			defer enforcerMutex.RUnlock()
			allowed, err := syncedCachedEnforcer.Enforce(role, req.URL.Path, req.Method)
			if err != nil {
				return nil, fmt.Errorf("权限检查错误: %w", err)
			}

			if allowed {
				req.Header.Set(constants.UserRoleMetadataKey, role)
				req.Header.Set(constants.UserOwner, userOwner)
				req.Header.Set(constants.UserIdMetadataKey, userID)
				return next.RoundTrip(req)
			}

			return nil, fmt.Errorf("%w: 角色%v无%s %s权限",
				NotAuthZ, role, req.Method, req.URL.Path)
		})
	}, nil
}

func getUserRoles(userID string) (string, error) {
	if cached, found := cache.Get(userID); found {
		return cached.(string), nil
	}

	role, err := fetchRolesFromCasdoor(userID)
	if err != nil {
		return "", err
	}

	cache.Set(userID, role)
	return role, nil
}

func fetchRolesFromCasdoor(userID string) (string, error) {
	id := fmt.Sprintf("%s/%s", userOwner, userID)
	req, _ := http.NewRequest("GET", fmt.Sprintf("%s/api/get-user?id=%s&owner=%s", casdoorUrl, id, userOwner), nil)
	q := req.URL.Query()
	// q.Add("owner", userOwner)
	req.URL.RawQuery = q.Encode()

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("casdoor接口调用失败: %w", err)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Warnf("关闭响应体失败: %v", err)
			return
		}
	}(resp.Body)

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
	if userID == result.Data.Id && len(result.Data.Roles) > 0 {
		role = result.Data.Roles[0].Name
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
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now().UnixNano()
	for k, v := range c.items {
		if now > v.expiration {
			delete(c.items, k)
		}
	}
}

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
