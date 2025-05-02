FROM python:3.9-slim

# 安装必要的依赖
RUN pip install --no-cache-dir requests flask

# 设置工作目录
WORKDIR /app

# 创建必要的目录
RUN mkdir -p /opt/sub_merger /var/log /app/static /app/templates

# 复制所有Python文件
COPY app/*.py /app/

# 复制模板文件
COPY app/templates/ /app/templates/

# 复制启动脚本
COPY scripts/entrypoint.sh /app/

# 设置执行权限
RUN chmod +x /app/subscription_service.py
RUN chmod +x /app/entrypoint.sh

# 创建符号链接
RUN ln -sf /app/subscription_service.py /opt/sub_merger/subscription_service.py

# 暴露端口
EXPOSE 25500

# 设置环境变量
ENV ACCESS_TOKEN=your_access_token_here
ENV PORT=25500
ENV ADMIN_USERNAME=admin
ENV ADMIN_PASSWORD=your_secure_password
ENV SECRET_KEY=your_secure_secret_key_for_sessions
ENV SERVICE_COMMUNICATION_TOKEN=your_secure_service_communication_token

# 启动命令
ENTRYPOINT ["/app/entrypoint.sh"]