package client

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-kratos/kratos/v2/selector"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/net/http2"

	config "github.com/go-kratos/gateway/api/gateway/config/v1"
	"github.com/go-kratos/gateway/middleware"
)

var (
	_               selector.Node = &node{}
	_globalClient                 = defaultClient()
	_globalH2Client               = defaultH2Client()
	_dialTimeout                  = 200 * time.Millisecond
	followRedirect                = false
)

func init() {
	var err error
	if v := os.Getenv("PROXY_DIAL_TIMEOUT"); v != "" {
		if _dialTimeout, err = time.ParseDuration(v); err != nil {
			panic(err)
		}
	}
	if val := os.Getenv("PROXY_FOLLOW_REDIRECT"); val != "" {
		followRedirect = true
	}
	prometheus.MustRegister(_metricClientRedirect)
}

var _metricClientRedirect = prometheus.NewCounterVec(prometheus.CounterOpts{
	Namespace: "go",
	Subsystem: "gateway",
	Name:      "client_redirect_total",
	Help:      "The total number of client redirect",
}, []string{"protocol", "method", "path", "service", "basePath"})

func defaultCheckRedirect(req *http.Request, via []*http.Request) error {
	labels, ok := middleware.MetricsLabelsFromContext(req.Context())
	if ok {
		_metricClientRedirect.WithLabelValues(labels.Protocol(), labels.Method(), labels.Path(), labels.Service(), labels.BasePath()).Inc()
	}
	if followRedirect {
		if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}
		return nil
	}
	return http.ErrUseLastResponse
}

func defaultClient() *http.Client {
	return &http.Client{
		CheckRedirect: defaultCheckRedirect,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   _dialTimeout,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			MaxIdleConns:          10000,
			MaxIdleConnsPerHost:   1000,
			MaxConnsPerHost:       1000,
			DisableCompression:    true,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
}

func defaultH2Client() *http.Client {
	return &http.Client{
		CheckRedirect: defaultCheckRedirect,
		Transport: &http2.Transport{
			// So http2.Transport doesn't complain the URL scheme isn't 'https'
			AllowHTTP:          true,
			DisableCompression: true,
			// 正确处理TLS连接
			// 使用传入的tls.Config或创建默认配置
			DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
				dialer := &net.Dialer{Timeout: _dialTimeout}
				conn, err := dialer.DialContext(ctx, network, addr)
				if err != nil {
					return nil, err
				}

				// 如果没有提供TLS配置，创建一个默认的
				tlsConfig := cfg
				if tlsConfig == nil {
					tlsConfig = &tls.Config{
						InsecureSkipVerify: true,
						MinVersion:         tls.VersionTLS12,
					}
				}

				// 返回TLS连接
				return tls.Client(conn, tlsConfig), nil
			},
		},
	}
}

func newNode(addr string, protocol config.Protocol, weight *int64, md map[string]string, version string, name string) *node {
	node := &node{
		protocol: protocol,
		address:  addr,
		weight:   weight,
		metadata: md,
		version:  version,
		name:     name,
	}
	if protocol == config.Protocol_GRPC {
		node.client = _globalH2Client
	} else {
		node.client = _globalClient
	}
	return node
}

type node struct {
	address  string
	name     string
	weight   *int64
	version  string
	metadata map[string]string

	client   *http.Client
	protocol config.Protocol
}

func (n *node) Scheme() string {
	return strings.ToLower(n.protocol.String())
}

func (n *node) Address() string {
	return n.address
}

// ServiceName is service name
func (n *node) ServiceName() string {
	return n.name
}

// InitialWeight is the initial value of scheduling weight
// if not set return nil
func (n *node) InitialWeight() *int64 {
	return n.weight
}

// Version is service node version
func (n *node) Version() string {
	return n.version
}

// Metadata is the kv pair metadata associated with the service instance.
// version,namespace,region,protocol etc..
func (n *node) Metadata() map[string]string {
	return n.metadata
}
