package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/go-kratos/gateway/discovery"
	"github.com/go-kratos/gateway/middleware"
	"github.com/go-kratos/gateway/proxy/auth"
	"net/http"
	"os"

	"time"

	"github.com/go-kratos/gateway/client"
	"github.com/go-kratos/gateway/config"
	configLoader "github.com/go-kratos/gateway/config/config-loader"

	"github.com/go-kratos/gateway/proxy"
	"github.com/go-kratos/gateway/proxy/debug"
	"github.com/go-kratos/gateway/server"

	_ "net/http/pprof"

	_ "github.com/go-kratos/gateway/discovery/consul" // Consul服务发现
	_ "github.com/go-kratos/gateway/middleware/bbr" // 负载均衡中间件
	"github.com/go-kratos/gateway/middleware/circuitbreaker" // 熔断中间件
	_ "github.com/go-kratos/gateway/middleware/cors" // CORS中间件
	_ "github.com/go-kratos/gateway/middleware/jwt" // JWT中间件
	_ "github.com/go-kratos/gateway/middleware/logging" // 日志中间件
	_ "github.com/go-kratos/gateway/middleware/rbac" // 权限中间件
	_ "github.com/go-kratos/gateway/middleware/rewrite" // 重写中间件
	_ "github.com/go-kratos/gateway/middleware/routerfilter" // 过滤中间件
	_ "github.com/go-kratos/gateway/middleware/tracing" // 链路追踪中间件
	_ "github.com/go-kratos/gateway/middleware/transcoder" // 编解码中间件
	_ "go.uber.org/automaxprocs"

	"github.com/go-kratos/kratos/v2"
	"github.com/go-kratos/kratos/v2/log"
	"github.com/go-kratos/kratos/v2/registry"
	"github.com/go-kratos/kratos/v2/transport"
	"golang.org/x/exp/rand"
)

var (
	ctrlName          string
	ctrlService       string
	discoveryDSN      string
	proxyAddrs        = newSliceVar(":8080")
	proxyConfig       string
	priorityConfigDir string
	withDebug         bool
)

type sliceVar struct {
	val        []string
	defaultVal []string
}

func newSliceVar(defaultVal ...string) sliceVar {
	return sliceVar{defaultVal: defaultVal}
}
func (s *sliceVar) Get() []string {
	if len(s.val) <= 0 {
		return s.defaultVal
	}
	return s.val
}
func (s *sliceVar) Set(val string) error {
	s.val = append(s.val, val)
	return nil
}
func (s *sliceVar) String() string { return fmt.Sprintf("%+v", *s) }

func init() {
	rand.Seed(uint64(time.Now().Nanosecond()))

	flag.BoolVar(&withDebug, "debug", true, "enable debug handlers")
	flag.Var(&proxyAddrs, "addr", "proxy address, eg: -addr 0.0.0.0:8080")
	flag.StringVar(&proxyConfig, "conf", "config.yaml", "config path, eg: -conf config.yaml")
	flag.StringVar(&priorityConfigDir, "conf.priority", "", "priority config directory, eg: -conf.priority ./canary")
	flag.StringVar(&ctrlName, "ctrl.name", os.Getenv("ADVERTISE_NAME"), "control gateway name, eg: gateway")
	flag.StringVar(&ctrlService, "ctrl.service", "", "control service host, eg: http://127.0.0.1:8000")
	flag.StringVar(&discoveryDSN, "discovery.dsn", "consul://99.suyiiyii.top:3026", "discovery dsn, eg: consul://127.0.0.1:7070?token=secret&datacenter=prod")
	// flag.StringVar(&discoveryDSN, "discovery.dsn", "consul://159.75.231.54:8500", "discovery dsn, eg: consul://127.0.0.1:7070?token=secret&datacenter=prod")
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
	// 解析 命令行选项及参数
	flag.Parse()

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
	servers := make([]transport.Server, 0, len(proxyAddrs.Get()))
	for _, addr := range proxyAddrs.Get() {
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
