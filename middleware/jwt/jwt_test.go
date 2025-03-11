package jwt

import "testing"

func TestSync(t *testing.T) {
	if err := syncPublicKey(); err != nil {
		t.Error("手动同步失败: ", err)
	} else {
		t.Log("手动同步成功")
	}
}
