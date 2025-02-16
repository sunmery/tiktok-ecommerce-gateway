package authN

import (
	"encoding/json"
	"github.com/go-kratos/gateway/proxy/auth"
	"github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"net/http"
	"time"
)

type LoginUser struct {
	Name     string `json:"Name"`
	Password string `json:"password"`
}

type UserDoc struct {
	Name     string             `bson:"Name"`
	Password string             `bson:"password"`
	ID       primitive.ObjectID `bson:"_id"`
}

func RegHandler(w http.ResponseWriter, r *http.Request) {
	var user LoginUser
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if user.Name == "" {
		http.Error(w, "用户名不能为空", http.StatusUnauthorized)
	}
	if user.Password == "" {
		http.Error(w, "密码不能为空", http.StatusUnauthorized)
	}
	_, err = auth.Db.Collection("users").InsertOne(r.Context(), user)
	if err != nil {
		panic(err)
	}
}

func GenerateJWT(Name, secretKey string) (string, error) {
	claims := auth.User{
		Name: Name,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)), // 过期时间1小时
			IssuedAt:  jwt.NewNumericDate(time.Now()),                    // 签发时间
			NotBefore: jwt.NewNumericDate(time.Now()),                    // 生效时间
		},
	}
	// 使用HS256签名算法
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	s, err := t.SignedString([]byte(secretKey))

	return s, err
}

// LoginHandler 处理登陆请求
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	var user LoginUser
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var userDoc UserDoc
	err = auth.Db.Collection("users").FindOne(r.Context(), bson.M{
		"Name":     user.Name,
		"password": user.Password,
	}).Decode(&userDoc)
	if err != nil || userDoc.ID.IsZero() {
		http.Error(w, "用户名或者密码错误", http.StatusUnauthorized)
		return
	}
	token, err := GenerateJWT(user.Name, "test_jwt")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"token": token,
	})
}
