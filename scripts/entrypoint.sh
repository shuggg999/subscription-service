#!/bin/sh

# 确保配置目录存在
mkdir -p /opt/sub_merger

# 从环境变量设置访问令牌
if [ -n "$ACCESS_TOKEN" ]; then
    echo "$ACCESS_TOKEN" > /opt/sub_merger/access_token.txt
    echo "已设置访问令牌"
fi

# 从环境变量设置端口
if [ -n "$PORT" ]; then
    echo "$PORT" > /opt/sub_merger/port.txt
    echo "已设置端口: $PORT"
fi

# 如果订阅文件不存在，创建一个空的
if [ ! -f "/opt/sub_merger/subscriptions.json" ]; then
    echo "[]" > /opt/sub_merger/subscriptions.json
    echo "已创建空订阅文件"
fi

# 确保日志文件存在
touch /var/log/sub_merger.log

# 启动订阅服务
echo "启动Python订阅服务..."
exec python /app/subscription_service.py --start