package loader

import (
	"fmt"
	"github.com/go-kratos/gateway/constants"
	"github.com/go-kratos/kratos/v2/log"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/hashicorp/consul/api"
)

type ConsulFileLoader struct {
	Client *api.Client
	Prefix string
}

func NewConsulFileLoader(address, prefix string) (*ConsulFileLoader, error) {
	client, err := api.NewClient(&api.Config{Address: address})
	if err != nil {
		return nil, err
	}
	return &ConsulFileLoader{Client: client, Prefix: prefix}, nil
}

func (l *ConsulFileLoader) DownloadFile(consulPath, localPath string) error {
	fullPath := path.Join(l.Prefix, consulPath)
	log.Debugf("[LOADER] 正在下载文件: consul://%s => %s", fullPath, localPath)

	kv, _, err := l.Client.KV().Get(fullPath, nil)
	if err != nil {
		return fmt.Errorf("consul请求失败: %w", err)
	}
	if kv == nil {
		return fmt.Errorf("文件不存在: %s", fullPath)
	}

	if err := os.WriteFile(localPath, kv.Value, 0644); err != nil {
		return fmt.Errorf("写入本地文件失败: %w", err)
	}

	log.Debugf("[LOADER] 下载成功: %s (大小: %d字节)", localPath, len(kv.Value))
	return nil
}

// DownloadEssentialFiles 下载Consul 远端文件
func DownloadEssentialFiles() {
	// 创建TLS, RBAC策略, 密钥目录
	requiredDirs := []string{
		filepath.Join(constants.ConfigDir, constants.TlsDirName), // 创建TLS目录
		filepath.Join(constants.ConfigDir, constants.SecretsDirName), // 创建密钥目录
		filepath.Join(constants.ConfigDir, constants.RBACDirName), // 创建RBAC目录
	}
	for _, dir := range requiredDirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
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
		fmt.Sprintf("%s/%s", constants.TlsDirName, constants.CrtFileName):
		filepath.Join(constants.ConfigDir, constants.TlsDirName, constants.CrtFileName),
		fmt.Sprintf("%s/%s", constants.TlsDirName, constants.KeyFileName):
		filepath.Join(constants.ConfigDir, constants.TlsDirName, constants.KeyFileName),
		// JWT 公钥
		fmt.Sprintf("%s/%s", constants.SecretsDirName, constants.JwtPublicFileName):
		filepath.Join(constants.ConfigDir, constants.SecretsDirName, constants.JwtPublicFileName),
		// RBAC 文件
		fmt.Sprintf("%s/%s", constants.RBACDirName, constants.PoliciesfileName):
		filepath.Join(constants.ConfigDir, constants.RBACDirName, constants.PoliciesfileName),
		fmt.Sprintf("%s/%s", constants.RBACDirName, constants.ModelFileFileName):
		filepath.Join(constants.ConfigDir, constants.RBACDirName, constants.ModelFileFileName),
	}

	for src, dst := range requiredFiles {
		if err := fileLoader.DownloadFile(src, dst); err != nil {
			log.Fatalf("文件下载失败 [%s -> %s]: %v", src, dst, err)
		}
		log.Infof("成功下载文件: %s -> %s", src, dst)
	}

}
