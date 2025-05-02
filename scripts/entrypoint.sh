#!/bin/bash
set -e

# 导出环境变量使pythons可以使用
export PYTHONPATH=/app:$PYTHONPATH

# 设置日志目录
mkdir -p /var/log/subscription
LOG_FILE="/var/log/subscription/app.log"

echo "启动订阅合并服务..."
echo "监听端口: $PORT"

# 确保数据目录存在
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

# 运行订阅服务
cd /app
python subscription_service.py --port $PORT >> $LOG_FILE 2>&1