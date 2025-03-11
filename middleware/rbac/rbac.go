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
	"github.com/hashicorp/consul/api"
	"github.com/hashicorp/consul/api/watch"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	consulPrefix = "ecommerce/gateway"
)

var (
	policyLoader         *loader.ConsulFileLoader
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
func InitEnforcer() {
	if initialized {
		return
	}

	// 初始化路径和日志
	initPaths()
	middleware.Register("rbac", Middleware)
	initialized = true

	initPolicyLoader()

	if err := initializeEnforcer(); err != nil {
		panic(fmt.Sprintf("RBAC初始化失败: %v", err))
	}

	go watchPolicyChanges()
	log.Println("[RBAC] 初始化完成，开始监听策略变更")
}

func initPaths() {
	if localModelFile == "" {
		localModelFile = filepath.Join(constants.ConfigDir, constants.RBACDirName, constants.ModelFileFileName)
	}
	if localPolicyFile == "" {
		localPolicyFile = filepath.Join(constants.ConfigDir, constants.RBACDirName, constants.PoliciesfileName)
	}

	if err := os.MkdirAll(filepath.Dir(localPolicyFile), 0755); err != nil {
		panic(fmt.Sprintf("创建策略目录失败: %v", err))
	}

	log.Printf("[RBAC] 策略文件路径: %s\n模型文件路径: %s", localPolicyFile, localModelFile)
	checkFileExists(localPolicyFile)
	checkFileExists(localModelFile)
}

func checkFileExists(path string) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		panic(fmt.Sprintf("文件不存在: %s", path))
	}
}

func initializeEnforcer() error {
	if err := syncPolicyFiles(); err != nil {
		return fmt.Errorf("策略文件同步失败: %w", err)
	}
	return createEnforcer()
}

func initPolicyLoader() {
	consulConfig := api.DefaultConfig()
	consulConfig.Address = strings.TrimPrefix(os.Getenv(constants.DiscoveryDsn), "consul://")

	client, err := api.NewClient(consulConfig)
	if err != nil {
		panic(fmt.Sprintf("创建Consul客户端失败: %v", err))
	}

	policyLoader = &loader.ConsulFileLoader{
		Client: client,
		Prefix: consulPrefix,
	}
}

func syncPolicyFiles() error {
	log.Println("[SYNC] 开始同步策略文件...")
	defer log.Println("[SYNC] 文件同步完成")

	if err := downloadFile(constants.PoliciesfileName, localPolicyFile); err != nil {
		return err
	}
	return downloadFile(constants.ModelFileFileName, localModelFile)
}

func downloadFile(remoteName, localPath string) error {
	log.Printf("[SYNC] 正在下载文件 %s => %s", remoteName, localPath)

	// 先下载到临时文件
	tempFile := localPath + ".tmp"
	defer os.Remove(tempFile)

	if err := policyLoader.DownloadFile(
		path.Join(constants.RBACDirName, remoteName),
		tempFile,
	); err != nil {
		return fmt.Errorf("文件下载失败: %w", err)
	}

	// 校验文件内容
	newContent, _ := os.ReadFile(tempFile)
	if len(newContent) == 0 {
		return fmt.Errorf("下载到空文件: %s", remoteName)
	}

	// 原子替换文件
	if err := os.Rename(tempFile, localPath); err != nil {
		return fmt.Errorf("文件替换失败: %w", err)
	}
	log.Printf("[SYNC] 文件更新成功: %s (大小: %d字节)", localPath, len(newContent))
	return nil
}

func createEnforcer() error {
	enforcerMutex.Lock()
	defer enforcerMutex.Unlock()

	if syncedCachedEnforcer != nil {
		syncedCachedEnforcer.StopAutoLoadPolicy()
	}

	modelContent, err := os.ReadFile(localModelFile)
	if err != nil {
		return fmt.Errorf("读取模型文件失败: %w", err)
	}
	log.Printf("[MODEL] 加载模型内容:\n%s", modelContent)

	m, _ := model.NewModelFromString(string(modelContent))
	adapter := fileadapter.NewAdapter(localPolicyFile)

	if syncedCachedEnforcer, err = casbin.NewSyncedCachedEnforcer(m, adapter); err != nil {
		return fmt.Errorf("创建执行器失败: %w", err)
	}

	syncedCachedEnforcer.StartAutoLoadPolicy(1 * time.Minute)
	return nil
}

func watchPolicyChanges() {
	startConsulWatch("rbac/policies.csv", onPolicyUpdate)
	startConsulWatch("rbac/model.conf", onModelUpdate)
}

func startConsulWatch(keyPath string, callback func()) {
	fullPath := path.Join(consulPrefix, keyPath)
	log.Printf("[WATCH] 启动监听: %s", fullPath)

	params := map[string]interface{}{
		"type": "key",
		"key":  fullPath,
	}

	watcher, err := watch.Parse(params)
	if err != nil {
		log.Printf("[WATCH] 创建监视器失败: %v", err)
		return
	}

	watcher.Handler = func(idx uint64, data interface{}) {
		if kv, ok := data.(*api.KVPair); ok {
			log.Printf("[WATCH] 检测到变更: %s (版本: %d)", fullPath, kv.ModifyIndex)
			callback()
		}
	}

	// 带重试的持续监听
	for {
		if err := watcher.RunWithClientAndHclog(policyLoader.Client, nil); err != nil {
			log.Printf("[WATCH] 监听错误: %v (5秒后重试)", err)
			time.Sleep(5 * time.Second)
		}
	}
}

func onPolicyUpdate() {
	log.Println("[UPDATE] 检测到策略变更，开始处理...")
	defer log.Println("[UPDATE] 策略处理完成")

	// 先同步最新策略文件
	if err := downloadFile(constants.PoliciesfileName, localPolicyFile); err != nil {
		log.Printf("[ERROR] 策略文件下载失败: %v", err)
		return
	}

	enforcerMutex.RLock()
	defer enforcerMutex.RUnlock()

	if err := syncedCachedEnforcer.LoadPolicy(); err != nil {
		log.Printf("[ERROR] 策略重载失败: %v", err)
		return
	}
	log.Println("[UPDATE] 策略重载成功")
}

func onModelUpdate() {
	log.Println("[UPDATE] 检测到模型变更，开始处理...")
	defer log.Println("[UPDATE] 模型处理完成")

	if err := reloadModelAndPolicy(); err != nil {
		log.Printf("[ERROR] 模型重载失败: %v", err)
		return
	}
	log.Println("[UPDATE] 模型更新成功")
}

func reloadModelAndPolicy() error {
	enforcerMutex.Lock()
	defer enforcerMutex.Unlock()

	log.Println("[RELOAD] 开始全量重载...")
	if err := syncPolicyFiles(); err != nil {
		return err
	}
	return createEnforcer()
}

// 以下缓存相关代码保持不变...

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

// 中间件和角色获取逻辑保持不变...

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
			log.Printf("关闭响应体失败: %v", err)
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

// 清理器保持原样...

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
