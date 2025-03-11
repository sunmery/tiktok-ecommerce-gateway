package jwt

import (
	"os"
	"testing"

	"github.com/go-kratos/kratos/v2/log"
)

func TestInit(t *testing.T) {
	log.SetLogger(log.NewStdLogger(os.Stdout))

	err := Init()
	if err != nil {
		t.Fatalf("初始化失败: %v", err)
	}
}
