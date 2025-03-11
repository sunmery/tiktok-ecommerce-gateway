package loader

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-kratos/gateway/constants"
	"github.com/go-kratos/kratos/v2/log"
	"github.com/hashicorp/consul/api/watch"

	"github.com/hashicorp/consul/api"
)

var (
	loaderInstance *ConsulFileLoader
	loaderOnce     sync.Once
)

type ConsulFileLoader struct {
	Client *api.Client
	Prefix string
	logger *log.Helper
}

func NewConsulFileLoader(address, prefix string) (*ConsulFileLoader, error) {
	client, err := api.NewClient(&api.Config{Address: address})
	if err != nil {
		return nil, err
	}
	return &ConsulFileLoader{
		Client: client,
		Prefix: prefix,
		logger: log.NewHelper(log.With(log.DefaultLogger, "module", "loader/consul")), // 初始化
	}, nil
}

// AtomicReplace 新增原子文件替换
func AtomicReplace(tempFile, targetFile string) error {
	if err := os.Rename(tempFile, targetFile); err != nil {
		return fmt.Errorf("文件替换失败: %w", err)
	}
	return nil
}

func GetConsulLoader() (*ConsulFileLoader, error) {
	loaderOnce.Do(func() {
		addr := strings.TrimPrefix(os.Getenv(constants.DiscoveryDsn), "consul://")
		client, err := api.NewClient(&api.Config{Address: addr})
		if err != nil {
			return
		}
		loaderInstance = &ConsulFileLoader{
			Client: client,
			Prefix: constants.DiscoveryPrefix,
			logger: log.NewHelper(log.With(
				log.DefaultLogger,
				"module", "loader/consul",
			)),
		}
	})
	if loaderInstance == nil {
		return nil, errors.New("初始化失败")
	}
	return loaderInstance, nil
}

// SyncFile 带验证的文件同步方法

func (l *ConsulFileLoader) SyncFile(remotePath, localPath string, validateFunc func(string) error) error {
	tempFile, err := os.CreateTemp(filepath.Dir(localPath), "tmp-*")
	if err != nil {
		return fmt.Errorf("创建临时文件失败: %w", err)
	}
	defer func() {
		tempFile.Close()
		if err := os.Remove(tempFile.Name()); err != nil {
			l.logger.Warnf("清理临时文件失败: %v", err)
		}
	}()

	if err := l.DownloadFile(remotePath, tempFile.Name()); err != nil {
		return fmt.Errorf("下载失败: %w", err)
	}

	// 强制同步文件内容到磁盘
	if err := tempFile.Sync(); err != nil {
		return fmt.Errorf("文件同步失败: %w", err)
	}

	if validateFunc != nil {
		if err := validateFunc(tempFile.Name()); err != nil {
			return fmt.Errorf("验证失败: %w", err)
		}
	}

	// 原子替换文件
	if err := os.Rename(tempFile.Name(), localPath); err != nil {
		return fmt.Errorf("文件替换失败: %w", err)
	}

	// l.logger.Infof("文件更新成功: %s (大小: %d字节)", localPath, tempFile.Size())
	l.logger.Infof("文件更新成功: %s ", localPath)
	return nil
}

// Watch 监听
func (l *ConsulFileLoader) Watch(consulKey string, callback func()) error {
	fullPath := path.Join(l.Prefix, consulKey)
	params := map[string]interface{}{
		"type": "key",
		"key":  fullPath,
	}

	watcher, err := watch.Parse(params)
	if err != nil {
		return err
	}

	watcher.Handler = func(idx uint64, data interface{}) {
		if _, ok := data.(*api.KVPair); ok {
			callback()
		}
	}

	go func() {
		for {
			if err := watcher.RunWithClientAndHclog(l.Client, nil); err != nil {
				log.Errorf("监听错误: %v (5秒后重试)", err)
				time.Sleep(5 * time.Second)
			}
		}
	}()

	return nil
}

// DownloadEssentialFiles 启动时下载Consul 远端文件到本地
func DownloadEssentialFiles() {
	// 创建TLS, RBAC策略, 密钥目录
	requiredDirs := []string{
		filepath.Join(constants.ConfigDir, constants.TlsDirName),     // 创建TLS目录
		filepath.Join(constants.ConfigDir, constants.SecretsDirName), // 创建密钥目录
		filepath.Join(constants.ConfigDir, constants.RBACDirName),    // 创建RBAC目录
	}
	for _, dir := range requiredDirs {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			log.Fatalf("创建目录失败 %s: %v", dir, err)
		}
		log.Infof("已创建 %s 目录",
			filepath.Join(constants.ConfigDir, dir),
		)
	}

	// 获取环境变量并去除consul://前缀
	dsn := strings.TrimPrefix(os.Getenv(constants.DiscoveryDsn), "consul://")

	fileLoader, err := NewConsulFileLoader(
		dsn,
		constants.DiscoveryPrefix,
	)
	if err != nil {
		log.Fatalf("Consul 文件加载器初始化失败: %v", err)
	}

	requiredFiles := map[string]string{
		// TLS 证书
		fmt.Sprintf("%s/%s", constants.TlsDirName, constants.CrtFileName): filepath.Join(constants.ConfigDir, constants.TlsDirName, constants.CrtFileName),
		fmt.Sprintf("%s/%s", constants.TlsDirName, constants.KeyFileName): filepath.Join(constants.ConfigDir, constants.TlsDirName, constants.KeyFileName),
		// JWT 公钥
		fmt.Sprintf("%s/%s", constants.SecretsDirName, constants.JwtPublicFileName): filepath.Join(constants.ConfigDir, constants.SecretsDirName, constants.JwtPublicFileName),
		// RBAC 文件
		fmt.Sprintf("%s/%s", constants.RBACDirName, constants.PoliciesfileName):  filepath.Join(constants.ConfigDir, constants.RBACDirName, constants.PoliciesfileName),
		fmt.Sprintf("%s/%s", constants.RBACDirName, constants.ModelFileFileName): filepath.Join(constants.ConfigDir, constants.RBACDirName, constants.ModelFileFileName),
	}

	for src, dst := range requiredFiles {
		if err := fileLoader.DownloadFile(src, dst); err != nil {
			log.Fatalf("文件下载失败 [%s -> %s]: %v", src, dst, err)
		}
		log.Infof("成功下载文件: %s -> %s", src, dst)
	}
}

func (l *ConsulFileLoader) DownloadFile(consulPath, localPath string) error {
	fullPath := path.Join(l.Prefix, consulPath)
	l.logger.Debugf("正在下载文件: consul://%s => %s", fullPath, localPath)

	kv, _, err := l.Client.KV().Get(fullPath, nil)
	if err != nil {
		return fmt.Errorf("consul请求失败: %w", err)
	}
	if kv == nil {
		return fmt.Errorf("文件不存在: %s", fullPath)
	}

	// 添加文件写入逻辑
	if err := os.WriteFile(localPath, kv.Value, 0o644); err != nil {
		return fmt.Errorf("写入本地文件失败: %w", err)
	}

	l.logger.Debugf("下载成功: %s (大小: %d字节)", localPath, len(kv.Value))
	return nil
}
