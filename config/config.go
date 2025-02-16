package config

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"time"

	configv1 "github.com/go-kratos/gateway/api/gateway/config/v1"
	"github.com/go-kratos/kratos/v2/log"
	"google.golang.org/protobuf/encoding/protojson"
	"sigs.k8s.io/yaml"
)

type OnChange func() error

// 配置加载接口
type ConfigLoader interface {
	Load(context.Context) (*configv1.Gateway, error)
	Watch(OnChange)
	Close()
}

// 文件加载器
type FileLoader struct {
	confPath           string            // conf file path
	confSHA256         string            // conf file hash
	priorityDirectory  string            // 优先级更高的配置目录
	priorityConfigHash map[string]string // priorityConfig hash
	watchCancel        context.CancelFunc
	lock               sync.RWMutex
	onChangeHandlers   []OnChange
}

// protojson 配置选项
var _jsonOptions = &protojson.UnmarshalOptions{DiscardUnknown: true}

// 创建文件加载器
func NewFileLoader(confPath string, priorityDirectory string) (*FileLoader, error) {
	fl := &FileLoader{
		confPath:          confPath,
		priorityDirectory: priorityDirectory,
	}
	if err := fl.initialize(); err != nil {
		return nil, err
	}
	return fl, nil
}

// 文件加载器初始化
func (f *FileLoader) initialize() error {
	if f.priorityDirectory != "" {
		if err := os.MkdirAll(f.priorityDirectory, 0755); err != nil {
			return err
		}
	}
	sha256hex, pfHash, err := f.configSHA256()
	if err != nil {
		return err
	}
	f.confSHA256 = sha256hex
	log.Infof("the initial config file sha256: %s", sha256hex)
	f.priorityConfigHash = pfHash
	log.Infof("the initial priority config file sha256 map: %+v", f.priorityConfigHash)

	// 开启一个协程 监听配置文件变化
	watchCtx, cancel := context.WithCancel(context.Background())
	f.watchCancel = cancel
	go f.watchproc(watchCtx)
	return nil
}

func sha256sum(in []byte) string {
	sum := sha256.Sum256(in)
	return hex.EncodeToString(sum[:])
}

// 获取配置 hash，根据计算的 hash ，判断配置文件是否发生修改
func (f *FileLoader) configSHA256() (string, map[string]string, error) {
	configData, err := os.ReadFile(f.confPath)
	if err != nil {
		return "", nil, err
	}
	hash := sha256sum(configData)
	phHash, err := f.priorityConfigSHA256()
	if err != nil {
		log.Warnf("failed to get priority config sha256: %+v", err)
	}
	return hash, phHash, nil
}

func (f *FileLoader) priorityConfigSHA256() (map[string]string, error) {
	if f.priorityDirectory == "" {
		return map[string]string{}, nil
	}
	entrys, err := os.ReadDir(f.priorityDirectory)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, e := range entrys {
		if e.IsDir() {
			continue
		}
		if filepath.Ext(e.Name()) != ".yaml" {
			continue
		}
		configData, err := os.ReadFile(filepath.Join(f.priorityDirectory, e.Name()))
		if err != nil {
			return nil, err
		}
		out[e.Name()] = sha256sum(configData)
	}
	return out, nil
}

// 加载配置文件内容反序列化到结构体
func (f *FileLoader) Load(_ context.Context) (*configv1.Gateway, error) {
	log.Infof("loading config file: %s", f.confPath)

	configData, err := os.ReadFile(f.confPath)
	if err != nil {
		return nil, err
	}

	jsonData, err := yaml.YAMLToJSON(configData)
	if err != nil {
		return nil, err
	}
	out := &configv1.Gateway{}
	if err := _jsonOptions.Unmarshal(jsonData, out); err != nil {
		return nil, err
	}
	if err := f.mergePriorityConfig(out); err != nil {
		log.Warnf("failed to merge priority config: %+v", err)
	}
	return out, nil
}

// join priorityDir 文件夹下所有配置，然后将所有配置合并到 conf path 输出的结构体中，覆盖源配置
func (f *FileLoader) mergePriorityConfig(dst *configv1.Gateway) error {
	if f.priorityDirectory == "" {
		return nil
	}
	entrys, err := os.ReadDir(f.priorityDirectory)
	if err != nil {
		return err
	}
	replaceOrPrependEndpoint := MakeReplaceOrPrependEndpointFn(dst.Endpoints)
	for _, e := range entrys {
		if e.IsDir() {
			continue
		}
		if filepath.Ext(e.Name()) != ".yaml" {
			continue
		}
		cfgPath := filepath.Join(f.priorityDirectory, e.Name())
		pCfg, err := f.parsePriorityConfig(cfgPath)
		if err != nil {
			log.Warnf("failed to parse priority config: %s: %+v, skip merge this file", cfgPath, err)
			continue
		}
		for _, e := range pCfg.Endpoints {
			dst.Endpoints = replaceOrPrependEndpoint(dst.Endpoints, e)
		}
		log.Infof("succeeded to merge priority config: %s, %d endpoints effected", cfgPath, len(pCfg.Endpoints))
	}
	return nil
}

// 解析配置
func (f *FileLoader) parsePriorityConfig(cfgPath string) (*configv1.PriorityConfig, error) {
	configData, err := os.ReadFile(cfgPath)
	if err != nil {
		return nil, err
	}
	jsonData, err := yaml.YAMLToJSON(configData)
	if err != nil {
		return nil, err
	}
	out := &configv1.PriorityConfig{}
	if err := _jsonOptions.Unmarshal(jsonData, out); err != nil {
		return nil, err
	}
	return out, nil
}

// 返回一个函数，用于替换源配置中的 endpoint，如果源配置中不存在，则添加到源配置中
func MakeReplaceOrPrependEndpointFn(origin []*configv1.Endpoint) func([]*configv1.Endpoint, *configv1.Endpoint) []*configv1.Endpoint {
	keyFn := func(e *configv1.Endpoint) string {
		return fmt.Sprintf("%s-%s", e.Method, e.Path)
	}
	index := map[string]int{}
	for i, e := range origin {
		index[keyFn(e)] = i
	}
	return func(dst []*configv1.Endpoint, item *configv1.Endpoint) []*configv1.Endpoint {
		idx, ok := index[keyFn(item)]
		if !ok {
			return append([]*configv1.Endpoint{item}, dst...)
		}
		dst[idx] = item
		return dst
	}
}

// 设置配置文件变更事件处理器
func (f *FileLoader) Watch(fn OnChange) {
	log.Info("add config file change event handler")
	f.lock.Lock()
	defer f.lock.Unlock()
	f.onChangeHandlers = append(f.onChangeHandlers, fn)
}

// 执行配置文件变更事件处理器
func (f *FileLoader) executeLoader() error {
	log.Info("execute config loader")
	f.lock.RLock()
	defer f.lock.RUnlock()

	var chainedError error
	for _, fn := range f.onChangeHandlers {
		if err := fn(); err != nil {
			log.Errorf("execute config loader error on handler: %+v: %+v", fn, err)
			chainedError = errors.New(err.Error())
		}
	}
	return chainedError
}

// 配置文件变更观察者 通过比对配置文件的 hash 值，判断配置文件是否发生变更
func (f *FileLoader) watchproc(ctx context.Context) {
	log.Info("start watch config file")
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second * 5): // 5s 轮询一次
		}
		// 使用匿名函数自调用，可以防止迭代产生的变量占用过多内存，且可能会导致频繁gc
		// 通过函数作用域，可以有效的解决这些问题
		func() {
			sha256hex, pfHash, err := f.configSHA256()
			if err != nil {
				log.Errorf("watch config file error: %+v", err)
				return
			}
			if sha256hex != f.confSHA256 || !reflect.DeepEqual(pfHash, f.priorityConfigHash) {
				log.Infof("config file changed, reload config, last sha256: %s, new sha256: %s, last pfHash: %+v, new pfHash: %+v", f.confSHA256, sha256hex, f.priorityConfigHash, pfHash)
				if err := f.executeLoader(); err != nil {
					log.Errorf("execute config loader error with new sha256: %s: %+v, config digest will not be changed until all loaders are succeeded", sha256hex, err)
					return
				}
				f.confSHA256 = sha256hex
				f.priorityConfigHash = pfHash
				return
			}
		}()
	}
}

// 关闭配置文件加载
func (f *FileLoader) Close() {
	f.watchCancel()
}

type InspectFileLoader struct {
	ConfPath           string            `json:"confPath"`
	ConfSHA256         string            `json:"confSha256"`
	PriorityConfigHash map[string]string `json:"priorityConfigHash"`
	OnChangeHandlers   int64             `json:"onChangeHandlers"`
}

// DebugHandler debug service handler
func (f *FileLoader) DebugHandler() http.Handler {
	debugMux := http.NewServeMux()
	debugMux.HandleFunc("/debug/config/inspect", func(rw http.ResponseWriter, r *http.Request) {
		out := &InspectFileLoader{
			ConfPath:           f.confPath,
			ConfSHA256:         f.confSHA256,
			PriorityConfigHash: f.priorityConfigHash,
			OnChangeHandlers:   int64(len(f.onChangeHandlers)),
		}
		rw.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(rw).Encode(out)
	})
	debugMux.HandleFunc("/debug/config/load", func(rw http.ResponseWriter, r *http.Request) {
		out, err := f.Load(context.Background())
		if err != nil {
			rw.WriteHeader(http.StatusInternalServerError)
			_, _ = rw.Write([]byte(err.Error()))
			return
		}
		rw.Header().Set("Content-Type", "application/json")
		b, _ := protojson.Marshal(out)
		_, _ = rw.Write(b)
	})
	debugMux.HandleFunc("/debug/config/version", func(rw http.ResponseWriter, r *http.Request) {
		out, err := f.Load(context.Background())
		if err != nil {
			rw.WriteHeader(http.StatusInternalServerError)
			_, _ = rw.Write([]byte(err.Error()))
			return
		}
		rw.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(rw).Encode(map[string]interface{}{
			"version": out.Version,
		})
	})
	return debugMux
}
