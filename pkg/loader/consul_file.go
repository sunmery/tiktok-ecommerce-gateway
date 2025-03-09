package loader

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/hashicorp/consul/api"
)

type ConsulFileLoader struct {
	client *api.Client
	prefix string
}

func NewConsulFileLoader(address, prefix string) (*ConsulFileLoader, error) {
	client, err := api.NewClient(&api.Config{Address: address})
	if err != nil {
		return nil, err
	}
	return &ConsulFileLoader{client: client, prefix: prefix}, nil
}

func (l *ConsulFileLoader) DownloadFile(consulPath, localPath string) error {
	kv, _, err := l.client.KV().Get(filepath.Join(l.prefix, consulPath), nil)
	if err != nil {
		return err
	}
	if kv == nil {
		return fmt.Errorf("file not found: %s", consulPath)
	}
	return os.WriteFile(localPath, kv.Value, 0644)
}
