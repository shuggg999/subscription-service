# GitHub Actions 自动构建指南

本指南将帮助您设置GitHub Actions，以便在代码推送到仓库时自动构建并推送Docker镜像到Docker Hub。

## 前提条件

1. 一个GitHub账户
2. 一个Docker Hub账户
3. 代码已推送到GitHub仓库

## 配置步骤

### 1. 准备Docker Hub访问令牌

1. 登录您的Docker Hub账户
2. 点击右上角的头像，选择"Account Settings"
3. 在左侧菜单中，选择"Security"
4. 点击"New Access Token"按钮
5. 输入令牌名称（例如"github-actions"）
6. 选择适当的权限（至少需要"Read & Write"权限）
7. 创建并复制生成的访问令牌（注意：令牌只会显示一次）

### 2. 在GitHub中设置Secret

1. 在GitHub上打开您的仓库
2. 点击"Settings"选项卡
3. 在左侧菜单中选择"Secrets and variables" > "Actions"
4. 点击"New repository secret"按钮
5. 添加以下两个secret：
   - 名称：`DOCKERHUB_USERNAME`，值：您的Docker Hub用户名
   - 名称：`DOCKERHUB_TOKEN`，值：您之前生成的Docker Hub访问令牌

### 3. 配置工作流文件

1. 在您的仓库中创建`.github/workflows`目录
2. 在该目录中创建`docker-build.yml`文件，内容如下（已为您创建）:

```yaml
name: 构建和推送订阅服务Docker镜像

on:
  push:
    branches: [ main, master ]  # 同时支持main和master分支
    paths-ignore:
      - '**.md'
      - '.gitignore'
  # 添加手动触发选项
  workflow_dispatch:

jobs:
  build-and-push:
    runs-on: ubuntu-latest
    steps:
      - name: 检出代码
        uses: actions/checkout@v3
      
      - name: 设置Docker Buildx
        uses: docker/setup-buildx-action@v2
      
      - name: 登录到DockerHub
        uses: docker/login-action@v2
        with:
          username: ${{ secrets.DOCKERHUB_USERNAME }}
          password: ${{ secrets.DOCKERHUB_TOKEN }}
      
      - name: 提取元数据（标签、标记）
        id: meta
        uses: docker/metadata-action@v4
        with:
          images: ${{ secrets.DOCKERHUB_USERNAME }}/subscription-service
          tags: |
            type=raw,value=latest
            type=ref,event=branch
            type=sha,format=short
      
      - name: 构建并推送订阅服务镜像
        uses: docker/build-push-action@v4
        with:
          context: .
          push: true
          tags: ${{ steps.meta.outputs.tags }}
          labels: ${{ steps.meta.outputs.labels }}
          cache-from: type=registry,ref=${{ secrets.DOCKERHUB_USERNAME }}/subscription-service:buildcache
          cache-to: type=registry,ref=${{ secrets.DOCKERHUB_USERNAME }}/subscription-service:buildcache,mode=max
```

## 工作流说明

这个工作流提供了以下功能：

1. **触发条件**：
   - 当代码推送到main或master分支时自动触发
   - 忽略对README.md等文档的更改
   - 支持手动触发（workflow_dispatch）

2. **构建功能**：
   - 使用Docker Buildx进行多平台构建
   - 自动为镜像打标签（latest、分支名、commit SHA）
   - 使用缓存加速构建过程

3. **推送目标**：
   - 自动推送到您的Docker Hub账户
   - 镜像名称格式：`您的用户名/subscription-service:标签`

## 使用方法

### 首次设置后

1. 将工作流文件提交并推送到您的仓库
2. GitHub将自动检测并启用该工作流
3. 您可以在仓库的"Actions"选项卡中查看工作流执行情况

### 手动触发构建

1. 在GitHub仓库页面，点击"Actions"选项卡
2. 在左侧菜单中选择"构建和推送订阅服务Docker镜像"
3. 点击"Run workflow"按钮
4. 选择要使用的分支
5. 点击"Run workflow"按钮开始构建

### 自动构建

只需将您的代码更改推送到main或master分支，GitHub Actions就会自动执行构建和推送过程。

## 故障排除

- **构建失败**：检查Actions日志以获取详细错误信息
- **无法推送到Docker Hub**：验证DOCKERHUB_USERNAME和DOCKERHUB_TOKEN是否正确设置
- **Dockerfile问题**：确保您的Dockerfile位于仓库根目录并且配置正确

## 定制化

您可以根据需要修改工作流文件，例如：

- 更改触发条件（例如，仅在特定文件更改时构建）
- 构建多个镜像或多架构镜像
- 添加测试步骤
- 配置通知
- 添加部署步骤 