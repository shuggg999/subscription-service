# 订阅服务

这是一个独立的订阅聚合服务，用于管理和合并多个VPN订阅源。

## 功能特点

- 支持多种VPN协议订阅聚合（VLESS、VMESS、Trojan、Shadowsocks）
- RESTful API 接口支持订阅管理
- 支持多种客户端订阅格式
- 基于令牌的API认证
- Web界面管理订阅源
- Docker容器化部署

## 环境要求

- Docker 和 Docker Compose
- 可公网访问的服务器（用于提供订阅服务）

## 快速开始

1. 克隆仓库：

```bash
git clone https://your-repository/subscription-service.git
cd subscription-service
```

2. 修改环境配置：

创建 `.env` 文件：

```
ACCESS_TOKEN=your_secure_access_token
ADMIN_USERNAME=admin
ADMIN_PASSWORD=your_secure_password
```

3. 启动服务：

```bash
docker-compose up -d
```

4. 访问管理界面：

在浏览器中打开 `http://your-server-ip:8080`

## API文档

### 获取订阅

```
GET /sub?token=your_access_token&target=v2ray
```

参数说明：
- `token`: 访问令牌
- `target`: 客户端类型，支持 v2ray、clash、shadowrocket、surge、quanx

### 获取订阅列表

```
GET /api/list?token=your_access_token
```

### 添加订阅

```
POST /api/add
```

表单参数：
- `token`: 访问令牌
- `name`: 订阅名称
- `url`: 订阅URL

### 删除订阅

```
POST /api/delete
```

表单参数：
- `token`: 访问令牌
- `index`: 订阅索引

## 安全说明

- 请确保更改默认访问令牌和管理员密码
- 可以在Nginx配置中启用HTTP基本认证
- 建议使用HTTPS加密保护API通信

## 配置文件说明

- `docker-compose.yml`: Docker服务配置
- `.env`: 环境变量配置
- `nginx/conf/default.conf`: Nginx代理配置

## 更新记录

### v1.0.0
- 初始版本发布