# syntax=docker/dockerfile:1
# https://docs.docker.com/go/dockerfile-reference/

# 定义基础镜像的 Golang 版本
ARG GOIMAGE=golang:1.23.3-alpine3.20

FROM --platform=$BUILDPLATFORM ${GOIMAGE} AS build
COPY . /src
WORKDIR /src

# 版本号
ARG VERSION=latest

# Go的环境变量, 例如alpine镜像不内置gcc,则关闭CGO很有效
ARG GOOS=linux
ARG GOARCH=amd64
ARG CGOENABLED=0

# Go的环境变量, 例如alpine镜像不内置gcc,则关闭CGO很有效
ARG GO_PROXY=https://proxy.golang.com.cn,direct

# 设置环境变量
# RUN go env -w GOPROXY=https://goproxy.cn,direct
RUN go env -w GOPROXY=$GO_PROXY

# 利用 Docker 层缓存机制，单独下载依赖项，提高后续构建速度。
# 使用缓存挂载和绑定挂载技术，避免不必要的文件复制到容器中。
RUN --mount=type=cache,target=/go/pkg/mod/ \
    --mount=type=bind,source=go.sum,target=go.sum \
    --mount=type=bind,source=go.mod,target=go.mod \
    go mod download -x

# 获取代码版本号，用于编译时标记二进制文件
RUN --mount=type=cache,target=/go/pkg/mod/ \
    --mount=type=bind,target=. \
    GOOS=$GOOS \
    GOARCH=$GOARCH \
    CGOENABLED=$CGOENABLED \
    go build -o /bin ./...
   # 带版本的形式: go build -ldflags="-X main.Version=${VERSION}" -o /bin/main .
   # 多个服务的形式: go build -o /bin/ ./...
COPY ./cmd/gateway /bin/configs

FROM alpine:latest AS final
# 从构建阶段复制编译好的 Go 应用程序到运行阶段
COPY --from=build /bin /app

WORKDIR /app

# 用户进程ID
ARG UID=10001

# 后端程序的HTTP/gRPC端口
ARG GATEWAY_PORT=8080

# 修改镜像源
# RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.ustc.edu.cn/g' /etc/apk/repositories

# 安装应用运行必需的系统证书和时区数据包
# RUN --mount=type=cache,target=/var/cache/apk \
#    apk --update add ca-certificates tzdata && update-ca-certificates

# RUN chmod 1777 /tmp
# # 创建一个非特权用户来运行应用，增强容器安全性
# RUN adduser --disabled-password --gecos "" --home "/nonexistent" --shell "/sbin/nologin" --no-create-home --uid "${UID}" appuser

# 设置时区为上海
# RUN ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
# RUN echo 'Asia/Shanghai' >/etc/timezone

# USER appuser

# 指定容器对外暴露的端口号
EXPOSE $GATEWAY_PORT

RUN mkdir -p /data/conf

# 设置容器启动时执行的命令
CMD ["./gateway", "-conf", "/data/conf"]

# 构建Docker所属的当前平台与架构的二进制文件, 进到当前的backend目录
# VERSION=dev
# REPOSITORY="team/backend"
# Docker 容器在 Linux 内核上运行，即便是在 macOS 或 Windows 环境中。
# 如果使用docker构建时传递 GOOS=darwin 会导致构建的二进制文件不兼容于 Linux 环境，从而出现 exec format error
# 所以在使用docker构建时的目标平台的GOOS应该为 linux，而非 darwin。
# docker build . \
#   --progress=plain \
#   -t ecommerce/gateway:dev \
#   --build-arg CGOENABLED=0 \
#   --build-arg GOIMAGE=golang:1.23.3-alpine3.20 \
#   --build-arg GOOS=linux \
#   --build-arg GOARCH=amd64 \
#   --build-arg VERSION=$VERSION \
#   --build-arg GATEWAY_PORT=8080

# 构建多架构的二进制文件, 需要在Docker Desktop 启用 containerd 映像存储
# https://docs.docker.com/desktop/containerd/#enable-the-containerd-image-store
# VERSION=v1.0.0
# REPOSITORY="ecommerce/gateway"
# GOOS=linux
# GOARCH=amd64
# HTTP_PORT=30001
# GRPC_PORT=30002
# PLATFORM_1=linux/amd64
# PLATFORM_2=linux/arm64
# docker buildx build . \
#   --progress=plain \
#   -t $REPOSITORY:$VERSION \
#   --build-arg CGOENABLED=0 \
#   --build-arg GOIMAGE=golang:1.23.3-alpine3.20 \
#   --build-arg VERSION=$VERSION \
#   --build-arg HTTP_PORT=$HTTP_PORT \
#   --build-arg GRPC_PORT=$GRPC_PORT \
#   --build-arg GOOS=$GOOS \
#   --build-arg GOARCH=$GOARCH \
#   --platform $PLATFORM_1,$PLATFORM_2 \
#   --load

# 推送
# register="ccr.ccs.tencentyun.com"
# docker tag $REPOSITORY:$VERSION $register/$REPOSITORY:$VERSION
# docker push $register/$REPOSITORY:$VERSION

# 拉取
# GOOS=linux
# GOARCH=amd64
# docker pull $register/$REPOSITORY:$VERSION --platform $GOOS/GOARCH

# 运行
# docker run \
# --rm \
# -p 8080:8080 \

