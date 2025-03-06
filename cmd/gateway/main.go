package main

import (
	"context"
	"github.com/go-kratos/gateway/client"
	"github.com/go-kratos/gateway/config"
	configLoader "github.com/go-kratos/gateway/config/config-loader"
	"github.com/go-kratos/gateway/discovery"
	"github.com/go-kratos/gateway/middleware"
	"github.com/go-kratos/gateway/proxy/auth"
	"golang.org/x/exp/rand"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-kratos/gateway/proxy"
	"github.com/go-kratos/gateway/proxy/debug"
	"github.com/go-kratos/gateway/server"

	_ "net/http/pprof"

	_ "github.com/go-kratos/gateway/discovery/consul"
	_ "github.com/go-kratos/gateway/middleware/bbr"
	"github.com/go-kratos/gateway/middleware/circuitbreaker"
	_ "github.com/go-kratos/gateway/middleware/cors"
	_ "github.com/go-kratos/gateway/middleware/jwt"
	_ "github.com/go-kratos/gateway/middleware/logging"
	_ "github.com/go-kratos/gateway/middleware/rbac"
	_ "github.com/go-kratos/gateway/middleware/rewrite"
	_ "github.com/go-kratos/gateway/middleware/routerfilter" // 添加这行
	_ "github.com/go-kratos/gateway/middleware/tracing"
	_ "github.com/go-kratos/gateway/middleware/transcoder"
	_ "go.uber.org/automaxprocs"

	"github.com/go-kratos/kratos/v2"
	"github.com/go-kratos/kratos/v2/log"
	"github.com/go-kratos/kratos/v2/registry"
	"github.com/go-kratos/kratos/v2/transport"
)

var (
	ctrlName          string
	ctrlService       string
	discoveryDSN      string
	proxyAddrs        []string
	proxyConfig       string
	priorityConfigDir string
	withDebug         bool
)

// 从环境变量读取配置
func initConfig() {
	rand.Seed(uint64(time.Now().Nanosecond()))
	// 代理地址解析优化
	envAddrs := os.Getenv("PROXY_ADDRS")
	if envAddrs == "" {
		// 环境变量未设置时使用默认值
		proxyAddrs = []string{":8080"}
	} else {
		// 处理可能存在的空元素（如 "8080,,8081"）
		splitAddrs := strings.Split(envAddrs, ",")
		validAddrs := make([]string, 0, len(splitAddrs))
		for _, addr := range splitAddrs {
			if trimmed := strings.TrimSpace(addr); trimmed != "" {
				validAddrs = append(validAddrs, trimmed)
			}
		}
		if len(validAddrs) == 0 {
			// 环境变量值无效时回退默认值
			proxyAddrs = []string{":8080"}
		} else {
			proxyAddrs = validAddrs
		}
	}
	withDebug = os.Getenv("DEBUG") == "true"
	proxyConfig = os.Getenv("CONFIG_PATH")
	if proxyConfig == "" {
		proxyConfig = "config.yaml" // 默认值
	}
	priorityConfigDir = os.Getenv("PRIORITY_CONFIG_DIR")
	ctrlName = os.Getenv("CTRL_NAME")
	if ctrlName == "" {
		ctrlName = os.Getenv("ADVERTISE_NAME")
	}
	ctrlService = os.Getenv("CTRL_SERVICE")
	discoveryDSN = os.Getenv("DISCOVERY_DSN")
	if discoveryDSN == ""  {
		discoveryDSN = "localhost:8500"
	}
}

func makeDiscovery() registry.Discovery {
	if discoveryDSN == "" {
		return nil
	}
	d, err := discovery.Create(discoveryDSN)
	if err != nil {
		log.Fatalf("failed to create discovery: %v", err)
	}
	return d
}

// 在main函数前添加以下中间件实现

func main() {
	// 初始化配置
	initConfig()

	// 根据传入的服务发现创建客户端工厂
	clientFactory := client.NewFactory(makeDiscovery())
	// 创建代理 New 函数会创建基本的路由 不会根据配置端点创建路由
	p, err := proxy.New(clientFactory, middleware.Create)
	if err != nil {
		log.Fatalf("failed to new proxy: %v", err)
	}
	circuitbreaker.Init(clientFactory)

	// 加载配置
	ctx := context.Background()
	var ctrlLoader *configLoader.CtrlConfigLoader
	if ctrlService != "" {
		log.Infof("setup control service to: %q", ctrlService)
		ctrlLoader = configLoader.New(ctrlName, ctrlService, proxyConfig, priorityConfigDir)
		if err := ctrlLoader.Load(ctx); err != nil {
			log.Errorf("failed to do initial load from control service: %v, using local config instead", err)
		}
		if err := ctrlLoader.LoadFeatures(ctx); err != nil {
			log.Errorf("failed to do initial feature load from control service: %v, using default value instead", err)
		}
		go ctrlLoader.Run(ctx)
	}

	confLoader, err := config.NewFileLoader(proxyConfig, priorityConfigDir)
	if err != nil {
		log.Fatalf("failed to create config file loader: %v", err)
	}
	defer confLoader.Close()
	bc, err := confLoader.Load(context.Background())
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	// 更新服务端点配置(包括中间件) 会重置路由表 根据端点配置，创建路由处理器
	// 路由处理器中 包含一个客户端以及中间件调用链
	if err := p.Update(bc); err != nil {
		log.Fatalf("failed to update service config: %v", err)
	}
	reloader := func() error {
		bc, err := confLoader.Load(context.Background())
		if err != nil {
			log.Errorf("failed to load config: %v", err)
			return err
		}
		if err := p.Update(bc); err != nil {
			log.Errorf("failed to update service config: %v", err)
			return err
		}
		log.Infof("config reloaded")
		return nil
	}
	confLoader.Watch(reloader)

	var serverHandler http.Handler = p
	if withDebug {
		debug.Register("proxy", p)
		debug.Register("config", confLoader)
		if ctrlLoader != nil {
			debug.Register("ctrl", ctrlLoader)
		}
		serverHandler = debug.MashupWithDebugHandler(p)
	}

	serverHandler = auth.Handler(serverHandler)

	servers := make([]transport.Server, 0, len(proxyAddrs))
	for _, addr := range proxyAddrs {
		servers = append(servers, server.NewProxy(serverHandler, addr))
	}
	app := kratos.New(
		kratos.Name(bc.Name),
		kratos.Context(ctx),
		kratos.Server(
			servers...,
		),
	)
	if err := app.Run(); err != nil {
		log.Errorf("failed to run servers: %v", err)
	}
}
