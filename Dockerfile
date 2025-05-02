FROM python:3.9-slim

# 安装依赖
RUN pip install --no-cache-dir requests

# 创建工作目录
WORKDIR /app

# 创建配置目录
RUN mkdir -p /opt/sub_merger /var/log

# 复制应用代码
COPY app/subscription_service.py /app/
COPY scripts/entrypoint.sh /app/

# 设置权限
RUN chmod +x /app/subscription_service.py
RUN chmod +x /app/entrypoint.sh

# 创建软链接
RUN ln -sf /app/subscription_service.py /opt/sub_merger/subscription_service.py

# 暴露端口
EXPOSE 25500

# 设置环境变量
ENV ACCESS_TOKEN=your_access_token_here
ENV PORT=25500
ENV ADMIN_USERNAME=admin
ENV ADMIN_PASSWORD=your_secure_password

# 启动服务
ENTRYPOINT ["/app/entrypoint.sh"]