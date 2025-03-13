package constants

// 环境变量
const (
	ProxyAddrs = "PROXY_ADDRS"

	// DiscoveryDsn 服务发现
	DiscoveryDsn = "DISCOVERY_DSN"
	// DiscoveryPrefix 服务发现前缀
	DiscoveryPrefix     = "ecommerce/gateway"
	DiscoveryConfigPath = "DISCOVERY_CONFIG_PATH"

	// PriorityConfigDir 优先级配置目录
	PriorityConfigDir = "PRIORITY_CONFIG"

	// JwtPubkeyPath JWT公钥路径
	JwtPubkeyPath = "JWT_PUBKEY_PATH"

	// UseTLS TLS 配置
	UseTLS  = "USE_TLS" // 是否使用TLS
	TlsDir  = "TLS_DIR"
	CrtFile = "CRT_FILE_PATH"
	KeyFile = "KEY_FILE_PATH"

	PoliciesfilePath = "POLICIES_FILE_PATH"
	ModelFilePath    = "MODEL_FILE_PATH"

	CasdoorUrl = "CASDOOR_URL"

	Debug = "Debug"

	// ServiceName 服务名
	ServiceName = "SERVICE_NAME"
	// ServiceAddr 服务地址
	ServiceAddr = "SERVICE_ADDR"
	// ServicePort 服务端口
	ServicePort = "SERVICE_PORT"
	// ServiceWeight 服务权重
	ServiceWeight = "SERVICE_WEIGHT"

	// ServiceTags 服务标签
	ServiceTags            = "SERVICE_TAGS"
	ProxyReadHeaderTimeout = "PROXY_READ_HEADER_TIMEOUT"
	ProxyReadTimeout       = "PROXY_READ_TIMEOUT"
	ProxyWriteTimeout      = "PROXY_WRITE_TIMEOUTT"
	ProxyIdleTimeout       = "PROXY_IDLE_TIMEOUT"
)

// 默认值
const (
	// ConfigDir 配置目录
	ConfigDir = "dynamic-config"

	// SecretsDirName 密钥目录, jwt公钥
	SecretsDirName    = "secrets"
	JwtPublicFileName = "public.pem"

	// UserOwner 用户组织
	UserOwner            = "tiktok"
	UserRoleMetadataKey  = "x-md-global-role"
	UserOwnerMetadataKey = "x-md-global-owner"
	UserIdMetadataKey    = "x-md-global-user-id"

	// RBACDirName 基于角色的访问控制
	RBACDirName       = "rbac"
	PoliciesfileName  = "policies.csv"
	ModelFileFileName = "model.conf"

	TlsDirName  = "tls"
	CrtFileName = "gateway.crt"
	KeyFileName = "gateway.key"
)
