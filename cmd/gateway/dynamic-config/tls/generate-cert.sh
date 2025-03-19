#!/usr/bin/env bash
set -eo pipefail

# 基础配置（可通过命令行参数覆盖）
: "${CERT_DIR:=$(dirname "$0")}"   # 默认证书存储目录
: "${DOMAIN:=gw.apikv.com}"         # 默认域名
: "${ALT_NAMES:=DNS:localhost,DNS:127.0.0.1,DNS:${DOMAIN},IP:127.0.0.1}" # SAN配置

# 文件路径配置
CERT_FILE="${CERT_DIR}/gateway.crt"
KEY_FILE="${CERT_DIR}/gateway.key"
CONFIG_FILE="${CERT_DIR}/openssl.cnf"

# 创建证书目录
mkdir -p "$CERT_DIR"

# 生成OpenSSL配置文件
cat > "$CONFIG_FILE" << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no
x509_extensions = v3_ca

[req_distinguished_name]
CN = $DOMAIN

[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = $ALT_NAMES

[v3_ca]
basicConstraints = CA:TRUE
keyUsage = digitalSignature, keyCertSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
EOF

# 生成ECC私钥（prime256v1曲线）
if ! openssl ecparam -genkey \
  -name prime256v1 \
  -out "$KEY_FILE" >/dev/null 2>&1; then
  echo "密钥生成失败" >&2
  exit 1
fi

# 生成自签名证书
if ! openssl req -x509 \
  -new \
  -key "$KEY_FILE" \
  -out "$CERT_FILE" \
  -days 365 \
  -config "$CONFIG_FILE" \
  -extensions v3_ca >/dev/null 2>&1; then
  echo "证书生成失败" >&2
  exit 1
fi

# 设置文件权限
chmod 600 "$KEY_FILE"
chmod 644 "$CERT_FILE"

# 验证证书信息
echo "证书生成成功，验证信息："
openssl x509 -in "$CERT_FILE" -text -noout | awk '
  /Subject:/ {print "  主题:", $0}
  /DNS:/ {print "  DNS记录:", $0}
  /IP Address:/ {print "  IP地址:", $0}
  /Not Before:/ {print "  有效期:", $0}
  /Not After :/ {print "         ", $0}
'

echo -e "\n文件路径："
echo "证书文件: $CERT_FILE"
echo "私钥文件: $KEY_FILE"
