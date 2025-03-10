package rbac

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	fileadapter "github.com/casbin/casbin/v2/persist/file-adapter"
	config "github.com/go-kratos/gateway/api/gateway/config/v1"
	"github.com/go-kratos/gateway/constants"
	"github.com/go-kratos/gateway/middleware"
	"github.com/go-kratos/gateway/pkg/loader"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	consulPrefix = "ecommerce/gateway" // Consul存储前缀
)

var (
	policyLoader         *loader.ConsulFileLoader
	NotAuthZ             = errors.New("权限不足")
	syncedCachedEnforcer *casbin.SyncedCachedEnforcer
	cache                = NewCache(5*time.Minute, 10*time.Minute)
	casdoorUrl           = os.Getenv(constants.CasdoorUrl)
	userOwner            = constants.UserOwner
	userIdMetadataKey    = constants.UserIdMetadataKey
	initialized          bool
	localPolicyFile      = os.Getenv(constants.PoliciesfilePath) // 策略文件路径
	localModelFile       = os.Getenv(constants.ModelFilePath)  // 模型文件路径
)

// InitEnforcer 初始化RBAC系统
func InitEnforcer() {
	if initialized {
		return
	}

	// 默认值
	if localModelFile == "" {
		localModelFile = filepath.Join(constants.ConfigDir, constants.RBACDirName, constants.ModelFileFileName)
	}
	if localPolicyFile == "" {
		localPolicyFile = filepath.Join(constants.ConfigDir, constants.RBACDirName, constants.PoliciesfileName)
	}

	// 确保目录存在
	if err := os.MkdirAll(filepath.Dir(localPolicyFile), 0755); err != nil {
		panic(fmt.Sprintf("创建策略目录失败: %v", err))
	}

	// 添加路径验证日志
	log.Printf("策略文件路径: %s", localPolicyFile)
	log.Printf("模型文件路径: %s", localModelFile)

	// 检查文件是否存在
	if _, err := os.Stat(localPolicyFile); os.IsNotExist(err) {
		panic(fmt.Sprintf("策略文件不存在: %s", localPolicyFile))
	}
	if _, err := os.Stat(localModelFile); os.IsNotExist(err) {
		panic(fmt.Sprintf("模型文件不存在: %s", localModelFile))
	}

	middleware.Register("rbac", Middleware)
	initialized = true

	// 创建策略目录
	if err := os.MkdirAll("./policies", 0755); err != nil {
		panic(fmt.Sprintf("创建策略目录失败: %v", err))
	}

	initPolicyLoader()

	// 首次同步策略文件
	if err := syncPolicyFiles(); err != nil {
		panic(fmt.Sprintf("初始化策略文件失败: %v", err))
	}

	// 创建执行器
	if err := createEnforcer(); err != nil {
		panic(fmt.Sprintf("创建enforcer失败: %v", err))
	}

	// 启动策略监听
	go watchPolicyChanges()
}

// initPolicyLoader 初始化Consul文件加载器
func initPolicyLoader() {
	consulAddr := strings.TrimPrefix(os.Getenv(constants.DiscoveryDsn), "consul://")
	var err error
	policyLoader, err = loader.NewConsulFileLoader(consulAddr, consulPrefix)
	if err != nil {
		panic(fmt.Sprintf("创建Consul文件加载器失败: %v", err))
	}
}

// syncPolicyFiles 同步策略和模型文件
func syncPolicyFiles() error {
	// 策略
	remotePolicyPath := filepath.Join(constants.RBACDirName, constants.PoliciesfileName)
	if err := policyLoader.DownloadFile(remotePolicyPath, localPolicyFile); err != nil {
		return fmt.Errorf("下载策略文件失败: %w (远程路径: %s)", err, remotePolicyPath)
	}

	// 模型
	remoteModelPath := filepath.Join( constants.RBACDirName, constants.ModelFileFileName)
	if err := policyLoader.DownloadFile(remoteModelPath, localModelFile); err != nil {
		return fmt.Errorf("下载模型文件失败: %w (远程路径: %s)", err, remoteModelPath)
	}
	return nil
}

// createEnforcer 创建Casbin执行器
func createEnforcer() error {
	// 加载RBAC模型
	modelContent, err := os.ReadFile(localModelFile)
	if err != nil {
		return fmt.Errorf("读取模型文件失败: %w (路径: %s)", err, localModelFile)
	}

	// 打印模型内容用于调试
	log.Printf("========= 加载的模型文件内容 =========")
	log.Printf("%s", modelContent)
	log.Printf("====================================")

	m, err := model.NewModelFromString(string(modelContent))
	if err != nil {
		return fmt.Errorf("解析模型失败: %w (内容: %s)", err, string(modelContent))
	}

	// 使用文件适配器
	adapter := fileadapter.NewAdapter(localPolicyFile)

	// 初始化带缓存的执行器
	syncedCachedEnforcer, err = casbin.NewSyncedCachedEnforcer(m, adapter)
	if err != nil {
		return fmt.Errorf("创建执行器失败: %w", err)
	}

	// 设置自动加载策略间隔
	syncedCachedEnforcer.StartAutoLoadPolicy(1 * time.Minute)
	return nil
}

// watchPolicyChanges 策略文件变化监听
func watchPolicyChanges() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		if checkPolicyUpdate() {
			log.Println("检测到策略变更，重新加载策略")
			if err := syncedCachedEnforcer.LoadPolicy(); err != nil {
				log.Printf("策略重载失败: %v", err)
			}
		}
	}
}

// checkPolicyUpdate 检查策略文件更新
func checkPolicyUpdate() bool {
	tempFile := localPolicyFile + ".tmp"
	defer os.Remove(tempFile) // 确保临时文件最终被清理

	// 1. 下载最新策略到临时文件
	consulPath := filepath.Join(constants.RBACDirName, constants.PoliciesfileName)
	if err := policyLoader.DownloadFile(consulPath, tempFile); err != nil {
		log.Printf("策略更新检查失败: %v", err)
		return false
	}

	// 2. 对比内容
	currentContent, _ := os.ReadFile(localPolicyFile)
	newContent, _ := os.ReadFile(tempFile)
	if string(currentContent) == string(newContent) {
		return false // 内容相同无需更新
	}

	// 3. 覆盖本地策略文件
	if err := os.Rename(tempFile, localPolicyFile); err != nil {
		log.Printf("策略文件替换失败: %v", err)
		return false
	}
	log.Printf("策略文件已更新")
	return true
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

type JwtOptions struct {
	SkipPaths []string `json:"skip_paths"`
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

			allowed, err := syncedCachedEnforcer.Enforce(role, req.URL.Path, req.Method)
			if err != nil {
				return nil, fmt.Errorf("权限检查错误: %w", err)
			}

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
	q.Add("owner", userOwner)
	req.URL.RawQuery = q.Encode()

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
