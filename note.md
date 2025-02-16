# kratos gateway 源码分析

kratos 网关执行链路

    HTTP -> Proxy -> Router -> Middleware -> Client -> Selector -> Node
1. HTTP 为 GATEGAY代理的服务层
2. Proxy 为 网关代理
3. Router 为 路由层 根据配置端点创建路由器
4. Middleware 为 中间件层 定义网关代理的拦截器
5. Client 为 客户端层 定义网关代理的调用客户端 ; 由 Factory 函数创建客户端，由 Selector 选择节点
6. Node 为节点层 定义网关代理的调用节点

## HTTP
    HTTP 层代码在server包中，proxy.go 中 ProxyServer 结构体嵌套一个 http server ，并声明了关于start stop方法

## Proxy
    Proxy 层代码在proxy包中
1. proxy.go
   - Proxy 定义网关结构体 
   ```go
    type Proxy struct {
        router            atomic.Value // 定义路由器 存储的路由器为 router 层的 Router 接口
        clientFactory     client.Factory // 定义客户端工厂
        Interceptors      interceptors // 定义拦截器
        middlewareFactory middleware.FactoryV2 // 定义中间件工厂
    }
   ```
        声明 New 方法构造 Proxy，并同时创建 Router (依赖路由层)
        声明 buildMiddleware buildEndpoint 方法创建中间件和端点
        声明 Update 方法通过 config 中的配置更新路由
        实现 ServeHTTP 方法，实现 Handler 接口，处理服务层的http请求，
        Proxy 将会被作为 ProxyServer 的 handler
   - Proxy 实现 ServeHTTP 方法，被 ProxyServer 直接作为 http Handler 使用，是网关的入口
   - middlewareFactory 中间件工厂，创建中间件，依赖 middleware 层
   - clientFactory 客户端工厂，创建客户端，依赖 client 层

## Router
      router 包中定义被代理的路由，router.go文件中定义了Router接口
```go
   type Router interface {
	    http.Handler // http服务
	    Handle(pattern, method, host string, handler http.Handler, closer io.Closer) error // 注册路由
	    SyncClose(ctx context.Context) error // 同步关闭资源
   }
```
mux 子目录定义了基于开源库 gorilla/mux 的路由实现
```go
type muxRouter struct {
	*mux.Router // 拥有 gorilla/mux 的路由器，在实现Router.Handle时，可以使用该路由器增强路由功能
	wg        *sync.WaitGroup // 等待组
	allCloser []io.Closer // io资源切片，使用 wg 进行同步 
}
```
muxRouter 是自定义的路由器，他实现了Router接口的所有方法
1. ServerHTTP 该方法为自定义路由器必须实现的方法，其会被 http.server 调用
2. Handle 方法，该方法注册路由
3. SyncClose 同步关闭资源

muxRouter 中的字段
1. *mux.Router gorilla/mux提供的路由器，muxRouter最终都会将路由处理委托给该路由器处理
2. 持有一个等待组 确保在 http 服务关闭时，Group 中还未处理完的协程，能继续处理，实现优雅关闭
3. io资源切片 这里只要是 Client 

Router 路由器可以完成路由功能，拦截端点，并选择正确的处理器进行处理，但是网关还需要根据端点的配置将路由转发给对应的服务，
此时可以使用代理，将Router代理，由代理对象处理客户端的选择，并将路由转发

## Middleware V2 版
该中间件形式为 http client 的中间件，是在 client 调用 http 请求之前时执行
1. FactoryV2 工厂模式 通过中间件配置创建具体中间件
2. MiddlewareV2 中间件接口 定义一个方法```Process(http.RoundTripper) http.RoundTripper```，以及中间件必须是一个io.Closer，可以关闭资源
```markdown
中间件接口实现:
1. Middleware 一个函数类型
2. withCloser 一个结构体，嵌套了 Middleware ，以及一个 io.Closer
3. emptyMiddleware 一个空结构体，一个空中间件，没有添加任何中间件功能
```
### Middleware 
为一个函数类型，他实现了 MiddlewareV2 中间件接口，且该函数类型函数签名和 MiddlewareV2.Process 接口元素一致，因此可以使用该类的函数变量作为中间件，该
函数类型实现的 io.Closer，是一个空的实现，说明使用该函数类型变量作为中间件，关闭资源的接口不会提供，中间件将会自行处理资源的关闭，而不是使用者通过接口关闭
**函数实现的 MiddlewareV2.Process ，则是直接调用中间件函数**

### 中间件注册

### 中间件原理

## Client
client 包定义客户端接口，以及客户端工厂，Node，以及注册中心监控器

### Client 接口
```go
type Client interface {
	http.RoundTripper // http客户端
	io.Closer 
}
// client 结构体实现了 Client 接口
type client struct {
   applier  *nodeApplier
   selector selector.Selector
}
```

### Factory 函数 根据端点的配置创建 Client
```type Factory func(*config.Endpoint) (Client, error)```

## Selector

## Node


## 总体逻辑：
1. 解析命令行参数及选项 获取对应的配置以及配置文件路径
2. 创建服务发现实例
3. 根据服务发现实例创建客户端工厂
4. 创建代理
   - 创建基本的静态路由器
   - 为代理设置客户端工厂
   - 为代理设置中间件工厂
   - 设置代理的拦截器
5. 加载配置
6. 根据配置的端点以及中间件更新代理路由配置
   - 根据客户端工厂创建客户端
     - 创建 nodeApplier  节点应用
     - 创建 selector  节点选择
   - 根据端点配置的中间件 创建中间件(局部) endpoints namespace
   - 根据中间件配置 创建中间件(全局) root namespace
   - 将客户端和中间件组装成 RoundTripper 链
   - 创建 http 处理器，在处理器中使用 RoundTripper 发起客户端调用，转发代理的请求
7. 创建代理服务器

### ServeHTTP 流程：
1. Proxy 代理实例的ServeHTTP 方法被 http.server 调用，该方法会调用路由的 ServeHTTP 方法
2. muxRouter 路由器实例的 ServeHTTP 则调用嵌套的 gorilla mux 的路由器的 ServeHTTP 方法
3. gorilla mux 的路由器的 ServeHTTP 方法，则会选择路由表中对应的路由处理器处理路由

### RoundTripper 流程：
1. RoundTripper 被 gorilla mux 端点的路由处理器作为发送请求的客户端调用，调用链被正式调用
2. 局部中间件 RoundTripper 调用
3. 全局中间件 RoundTripper 调用
4. 客户端 RoundTripper 调用
   - 从 context 中获取 request opts
   - 从 context 中获取 filter
   - 使用client(自定义的结构体)实例中的 selector 选择从 nodes 中选择节点
   - 使用 client(http包).do 发送 http 请求

### nodes 节点:
1. 客户端工厂在创建客户端时，会设置客户端 nodeApplier 以及 selector
2. 创建 nodeApplier 时，设置服务发现实例以及节点配置信息
3. 调用 nodeApplier.Apply 应用节点配置信息，参加节点
4. 如果节点配置为具体后端地址，则直接创建节点，并存储到 selector 的 nodes 切片，如果节点配置为服务发现，则添加监控器，监控节点的变化

#### discovery watch 服务发现实现:
```go
// 服务监控结构
type serviceWatcher struct {
   lock          sync.RWMutex
   watcherStatus map[string]*watcherStatus // 根据端点的名称缓存者服务实例切片
   appliers      map[string]map[string]Applier // endpoint namespace -> node id -> node Applier
}
// 服务监控状态结构
type watcherStatus struct {
	watcher           registry.Watcher // 注册中心监控
	initializedChan   chan struct{} // 初始化完成信号
	selectedInstances []*registry.ServiceInstance // 监控到的服务实例
}
```
AddWatch(ctx, na.registry, target.Endpoint, na) 为当前端点配置的注册中心创建观察对象，并使用 nodeApplier 的回调将服务列表设置到 selector 中
1. 使用 globalServiceWatcher 全局的服务观察实例，添加观察者
2. 查看观察者状态，检验该端点是否已经创建过观察者，如果有则直接使用
3. 如果没有则创建观察者，并创建观察者
   - 使用注册中心，创建对应的观察者实例
   ```markdown
      Registry.Watch() 方法创建观察者实例步骤:
      1. 根据端点名称尝试从注册中心获取 serviceSet
      2. 如果不存在，则新建一个，并初始化字段，并在方法最后调用 Registry.resolve 处理 新建的 serviceSet
      3. 初始化一个 watcher 观察者
      4. 如果 serviceSet 不为空，发送一个事件，通知观察者服务发生变化
      Registry.resolve() 方法处理 serviceSet 步骤:
      5. 从 consul client 中获取服务列表，如果服务列表不为空，广播服务变化事件
      6. 开启协程，创建一个定时器轮询 consul client 服务的变化，并如果发生变化，广播事件(w.event)
   ```
   - 尝试从新创建的观察者实例获取服务列表
   - 创建协程，循环等待服务变更事件，```services, err := watcher.Next()```，注意 watcher.Next() 实际上会阻塞，直到服务列表发生变化
4. consul watcher.Next() 的实现
   - 使用一个 select 监听多个管道的值
     1. w.ctx.Done() 监听上下文信号
     2. w.event 
   - 获取 service 并返回错误(如果```context```上下文取消或者超时时，通过```context.Err()```返回错误)

### 关于 Debug service
命令行选项提供一个flag withDebug 控制是否开启 debug service
debug 包中提供一个全局的 debugService 指针 globalService，该变量创建一个路由，以及一个map存储了一些debug的path以及处理器
```go
// 初始化的debug路由
handlers: map[string]http.HandlerFunc{
"/debug/ping":               func(rw http.ResponseWriter, r *http.Request) {},
"/debug/pprof/":             pprof.Index,
"/debug/pprof/cmdline":      pprof.Cmdline,
"/debug/pprof/profile":      pprof.Profile,
"/debug/pprof/symbol":       pprof.Symbol,
"/debug/pprof/trace":        pprof.Trace,
"/debug/pprof/allocs":       pprof.Handler("allocs").ServeHTTP,
"/debug/pprof/block":        pprof.Handler("block").ServeHTTP,
"/debug/pprof/goroutine":    pprof.Handler("goroutine").ServeHTTP,
"/debug/pprof/heap":         pprof.Handler("heap").ServeHTTP,
"/debug/pprof/mutex":        pprof.Handler("mutex").ServeHTTP,
"/debug/pprof/threadcreate": pprof.Handler("threadcreate").ServeHTTP,
}
// 通过 debug 包的 Register 函数注册的
// 1. main 函数中
debug.Register("proxy", p)
debug.Register("config", confLoader)
if ctrlLoader != nil {
   debug.Register("ctrl", ctrlLoader)
}
// 2. serviceWatch 中
func (s *serviceWatcher) DebugHandler() http.Handler {
   debugMux := http.NewServeMux()
   debugMux.HandleFunc("/debug/watcher/nodes", func(w http.ResponseWriter, r *http.Request) {
   service := r.URL.Query().Get("service")
   nodes, _ := s.getSelectedCache(service)
   w.Header().Set("Content-Type", "application/json")
   json.NewEncoder(w).Encode(nodes)
   })
   debugMux.HandleFunc("/debug/watcher/appliers", func(w http.ResponseWriter, r *http.Request) {
   service := r.URL.Query().Get("service")
   appliers, _ := s.getAppliers(service)
   w.Header().Set("Content-Type", "application/json")
   json.NewEncoder(w).Encode(appliers)
   })
   return debugMux
}
```
1. Registry 会根据 path 前缀进行分组
2. 需要使用 Registry 注册路由，需要实现 Debuggable 接口的 ```DebugHandler() http.Handler```方法
3. debug.MashupWithDebugHandler(p) 使用装饰器模板包装 Proxy Handler
```go
// 如果路由中包括 debug 的前缀，则使用 globalService 处理，否则使用 Proxy 处理，走代理流程
func MashupWithDebugHandler(origin http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if strings.HasPrefix(req.URL.Path, _debugPrefix) {
			rmux.ProtectedHandler(globalService).ServeHTTP(w, req)
			return
		}
		origin.ServeHTTP(w, req)
	})
}
```
4. debugService ServeHTTP 通过简单的路径比对，处理静态路由，动态注册(Registry方法注册的)的则根据 gorilla mux 的路由规则分组，由 gorilla mux 负责路由功能

### config 

#### ConfigLoader
1. Load 加载配置文件，将配置内容反序列化到 go 结构体
2. Watch 设置配置文件变更事件处理器
3. Close 关闭资源

#### FileLoader
1. initialize 方法初始化文件加载器，计算配置文件 hash ，存储到对应的字段，并开启文件监听
2. watchproc 5s 钟轮询，检查文件 hash 是否发生变化，发生变化则重新加载配置文件
3. executeLoader 通过调用回掉函数执行加载配置
4. Load 加载配置文件中的配置，由回调函数调用

#### CtrlConfigLoader
从控制系统(配置中心)中加载配置

### 设计模式的使用
1. 装饰器模式 
   - 中间件和客户端 func(http.RoundTripper) http.RoundTripper
   - MashupWithDebugHandler ProtectedHandler
2. 代理模式 Proxy
3. 工厂方法模式 中间件和客户端
4. 适配器模式(函数) RoundTripperFunc 和 Middleware
5. 观察者模式 Watcher 
6. 选项模式 Factory
7. 还有很多优雅的go程序解决方案，http服务的优雅停止，context的使用, atomic.Value的使用, RWMutex 的使用, goroutine 和 channel 的使用

