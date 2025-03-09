package rbac

import (
	"os"
	"testing"
)

func TestFileOperations(t *testing.T) {
	// 测试读取
	if _, err := os.ReadFile("testfile"); err != nil {
		t.Fatal("文件读取失败")
	}

	// 测试写入
	testData := []byte("test content")
	if err := os.WriteFile("testfile", testData, 0644); err != nil {
		t.Fatal("文件写入失败")
	}

	// 清理
	os.Remove("testfile")
}
