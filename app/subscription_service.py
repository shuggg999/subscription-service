#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import base64
import urllib.request
import urllib.parse
import re
import time
import socket
import logging
from http.server import HTTPServer, BaseHTTPRequestHandler
import subprocess
import threading
import argparse
from pathlib import Path
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, render_template, redirect, url_for, abort
from models import UserManager, SubscriptionManager
from auth_api import auth_api

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("/var/log/sub_merger.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("SubscriptionService")

# 配置目录
CONFIG_DIR = "/opt/sub_merger"
SUBSCRIPTIONS_FILE = os.path.join(CONFIG_DIR, "subscriptions.json")
ACCESS_TOKEN_FILE = os.path.join(CONFIG_DIR, "access_token.txt")
ADMIN_CREDENTIALS_FILE = os.path.join(CONFIG_DIR, "admin_credentials.json")
USERS_FILE = os.path.join(CONFIG_DIR, "users.json")
PORT_FILE = os.path.join(CONFIG_DIR, "port.txt")
DEFAULT_PORT = 25500
DEFAULT_TOKEN = "your_access_token_here"
DEFAULT_ADMIN_USERNAME = "admin"
DEFAULT_ADMIN_PASSWORD = "your_secure_password"

# 确保配置目录存在
os.makedirs(CONFIG_DIR, exist_ok=True)

# 散列密码
def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    pwdhash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), 
                                   salt.encode('utf-8'), 100000)
    return f"{salt}${pwdhash.hex()}"

# 验证密码
def verify_password(stored_password, provided_password):
    salt, hash = stored_password.split('$')
    return stored_password == hash_password(provided_password, salt)

# 初始化管理员凭据
def init_admin_credentials():
    if not os.path.exists(ADMIN_CREDENTIALS_FILE):
        admin_username = os.environ.get("ADMIN_USERNAME", DEFAULT_ADMIN_USERNAME)
        admin_password = os.environ.get("ADMIN_PASSWORD", DEFAULT_ADMIN_PASSWORD)
        
        credentials = {
            "username": admin_username,
            "password": hash_password(admin_password)
        }
        
        try:
            with open(ADMIN_CREDENTIALS_FILE, 'w') as f:
                json.dump(credentials, f)
            logger.info("已创建管理员凭据")
        except Exception as e:
            logger.error(f"创建管理员凭据失败: {e}")

# 初始化用户
def init_users():
    if not os.path.exists(USERS_FILE):
        try:
            with open(USERS_FILE, 'w') as f:
                json.dump([], f)
            logger.info("已创建用户文件")
        except Exception as e:
            logger.error(f"创建用户文件失败: {e}")

# 读取或创建订阅文件
def load_subscriptions():
    if os.path.exists(SUBSCRIPTIONS_FILE):
        try:
            with open(SUBSCRIPTIONS_FILE, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"读取订阅文件失败: {e}")
            return []
    else:
        return []

# 保存订阅
def save_subscriptions(subscriptions):
    try:
        with open(SUBSCRIPTIONS_FILE, 'w') as f:
            json.dump(subscriptions, f, indent=2)
        return True
    except Exception as e:
        logger.error(f"保存订阅文件失败: {e}")
        return False

# 读取访问令牌
def load_access_token():
    if os.path.exists(ACCESS_TOKEN_FILE):
        try:
            with open(ACCESS_TOKEN_FILE, 'r') as f:
                return f.read().strip()
        except Exception as e:
            logger.error(f"读取访问令牌失败: {e}")
            return DEFAULT_TOKEN
    else:
        # 如果文件不存在，创建默认的
        try:
            # 从环境变量读取，如果存在
            token = os.environ.get("ACCESS_TOKEN", DEFAULT_TOKEN)
            with open(ACCESS_TOKEN_FILE, 'w') as f:
                f.write(token)
            return token
        except Exception as e:
            logger.error(f"创建访问令牌文件失败: {e}")
            return DEFAULT_TOKEN

# 保存访问令牌
def save_access_token(token):
    try:
        with open(ACCESS_TOKEN_FILE, 'w') as f:
            f.write(token)
        return True
    except Exception as e:
        logger.error(f"保存访问令牌失败: {e}")
        return False

# 读取端口
def load_port():
    if os.path.exists(PORT_FILE):
        try:
            with open(PORT_FILE, 'r') as f:
                return int(f.read().strip())
        except Exception as e:
            logger.error(f"读取端口失败: {e}")
            return DEFAULT_PORT
    else:
        # 如果文件不存在，创建默认的
        try:
            # 从环境变量读取，如果存在
            port = int(os.environ.get("PORT", DEFAULT_PORT))
            with open(PORT_FILE, 'w') as f:
                f.write(str(port))
            return port
        except Exception as e:
            logger.error(f"创建端口文件失败: {e}")
            return DEFAULT_PORT

# 获取外部IP
def get_external_ip():
    try:
        external_ip = urllib.request.urlopen('https://api.ipify.org').read().decode('utf8')
        return external_ip
    except Exception as e:
        logger.error(f"获取外部IP失败: {e}")
        try:
            external_ip = urllib.request.urlopen('https://ifconfig.me').read().decode('utf8')
            return external_ip
        except Exception as e:
            logger.error(f"备用方法获取外部IP失败: {e}")
            # 使用socket获取本地IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                # 不需要真正连接
                s.connect(('10.255.255.255', 1))
                local_ip = s.getsockname()[0]
            except Exception:
                local_ip = '127.0.0.1'
            finally:
                s.close()
            return local_ip

# 下载订阅内容
def download_subscription(url):
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml',
        }
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=10) as response:
            content = response.read().decode('utf-8')
            return content.strip()
    except Exception as e:
        logger.error(f"下载订阅 {url} 失败: {e}")
        return None

# 判断是否是Base64编码
def is_base64(content):
    try:
        base64_pattern = r'^[A-Za-z0-9+/]+={0,2}$'
        return bool(re.match(base64_pattern, content))
    except Exception:
        return False

# 解码订阅内容
def decode_subscription(content):
    # 如果内容已经是协议链接开头，直接返回
    if content and any(content.startswith(prefix) for prefix in ('vless://', 'vmess://', 'trojan://', 'ss://')):
        return content
    
    # 尝试Base64解码
    if content and is_base64(content):
        try:
            decoded = base64.b64decode(content).decode('utf-8')
            if any(decoded.startswith(prefix) for prefix in ('vless://', 'vmess://', 'trojan://', 'ss://')):
                return decoded
            else:
                # 可能是多行base64
                lines = decoded.strip().split('\n')
                valid_links = [line for line in lines if any(line.startswith(prefix) for prefix in ('vless://', 'vmess://', 'trojan://', 'ss://'))]
                if valid_links:
                    return '\n'.join(valid_links)
        except Exception as e:
            logger.error(f"Base64解码失败: {e}")
    
    # 如果还没有有效链接，再尝试按行解析
    if content:
        lines = content.strip().split('\n')
        valid_links = []
        
        for line in lines:
            line = line.strip()
            # 直接检查是否是有效链接
            if any(line.startswith(prefix) for prefix in ('vless://', 'vmess://', 'trojan://', 'ss://')):
                valid_links.append(line)
            # 尝试作为Base64解码单行
            elif is_base64(line):
                try:
                    decoded_line = base64.b64decode(line).decode('utf-8')
                    if any(decoded_line.startswith(prefix) for prefix in ('vless://', 'vmess://', 'trojan://', 'ss://')):
                        valid_links.append(decoded_line)
                except Exception:
                    pass
        
        if valid_links:
            return '\n'.join(valid_links)
    
    # 如果所有尝试都失败，返回原始内容
    if content:
        logger.warning(f"无法解析订阅内容格式: {content[:100]}...")
    return content if content else ""

# 合并订阅
def merge_subscriptions(subscription_urls):
    merged_links = []
    
    for url in subscription_urls:
        content = download_subscription(url)
        if content:
            decoded_content = decode_subscription(content)
            if decoded_content:
                # 分割多行并添加到列表
                links = decoded_content.strip().split('\n')
                merged_links.extend([link for link in links if link.strip()])
    
    # 去重
    unique_links = list(dict.fromkeys(merged_links))
    
    # 返回合并的链接
    return '\n'.join(unique_links)

# 转换为各种客户端格式
def convert_to_client_format(content, client_type):
    # 目前仅支持直接返回原始内容，未来可以扩展为不同客户端格式的转换
    if client_type.lower() in ['v2ray', 'shadowrocket', 'surge', 'clash', 'quanx']:
        # Base64编码结果，符合大多数客户端期望
        if content:
            encoded_content = base64.b64encode(content.encode('utf-8')).decode('utf-8')
            return encoded_content
    
    return content

# 生成合并的订阅链接
def generate_subscription_links(server_ip, port, token):
    base_url = f"http://{server_ip}:{port}/sub?token={token}"
    
    links = {
        "v2ray": f"{base_url}&target=v2ray",
        "clash": f"{base_url}&target=clash",
        "shadowrocket": f"{base_url}&target=shadowrocket",
        "surge": f"{base_url}&target=surge",
        "quanx": f"{base_url}&target=quanx"
    }
    
    return links

# HTTP服务器处理程序
class SubRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            # 解析路径和查询参数
            parsed_path = urllib.parse.urlparse(self.path)
            query_params = urllib.parse.parse_qs(parsed_path.query)
            
            # 健康检查
            if parsed_path.path == '/ping':
                self.send_response(200)
                self.send_header('Content-type', 'text/plain; charset=utf-8')
                self.end_headers()
                self.wfile.write("Service OK".encode('utf-8'))
                return
                
            # 检查访问令牌
            if parsed_path.path == '/sub':
                access_token = load_access_token()
                client_token = query_params.get('token', [''])[0]
                
                if client_token != access_token:
                    self.send_response(403)
                    self.send_header('Content-type', 'text/plain; charset=utf-8')
                    self.end_headers()
                    self.wfile.write("访问令牌无效".encode('utf-8'))
                    return
                
                # 获取请求的目标客户端类型
                target = query_params.get('target', ['v2ray'])[0].lower()
                
                # 处理订阅
                subscriptions = load_subscriptions()
                subscription_urls = [sub["url"] for sub in subscriptions]
                
                if not subscription_urls:
                    self.send_response(404)
                    self.send_header('Content-type', 'text/plain; charset=utf-8')
                    self.end_headers()
                    self.wfile.write("未配置订阅源".encode('utf-8'))
                    return
                
                # 合并订阅
                merged_content = merge_subscriptions(subscription_urls)
                
                if not merged_content:
                    self.send_response(404)
                    self.send_header('Content-type', 'text/plain; charset=utf-8')
                    self.end_headers()
                    self.wfile.write("无法获取有效的订阅内容".encode('utf-8'))
                    return
                
                # 转换为客户端格式
                formatted_content = convert_to_client_format(merged_content, target)
                
                # 发送响应
                self.send_response(200)
                self.send_header('Content-type', 'text/plain; charset=utf-8')
                self.end_headers()
                self.wfile.write(formatted_content.encode('utf-8'))
                return
            
            # 订阅列表API
            if parsed_path.path == '/api/list':
                access_token = load_access_token()
                client_token = query_params.get('token', [''])[0]
                
                if client_token != access_token:
                    self.send_response(403)
                    self.send_header('Content-type', 'application/json; charset=utf-8')
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": "访问令牌无效"}).encode('utf-8'))
                    return
                
                subscriptions = load_subscriptions()
                
                self.send_response(200)
                self.send_header('Content-type', 'application/json; charset=utf-8')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(json.dumps({
                    "success": True,
                    "subscriptions": subscriptions
                }).encode('utf-8'))
                return
                
            # 其他路径返回404
            self.send_response(404)
            self.send_header('Content-type', 'text/plain; charset=utf-8')
            self.end_headers()
            self.wfile.write("路径不存在".encode('utf-8'))
            
        except Exception as e:
            logger.error(f"处理请求出错: {e}")
            self.send_response(500)
            self.send_header('Content-type', 'text/plain; charset=utf-8')
            self.end_headers()
            self.wfile.write("服务器内部错误".encode('utf-8'))
    
    def do_POST(self):
        try:
            # 解析路径和查询参数
            parsed_path = urllib.parse.urlparse(self.path)
            
            # 读取请求内容
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode('utf-8')
            
            # 解析JSON数据
            try:
                data = json.loads(post_data)
            except:
                data = urllib.parse.parse_qs(post_data)
                # 将列表值转为单个值
                data = {k: v[0] for k, v in data.items()}
            
            # 添加订阅API
            if parsed_path.path == '/api/add':
                access_token = load_access_token()
                client_token = data.get('token', '')
                
                if client_token != access_token:
                    self.send_response(403)
                    self.send_header('Content-type', 'application/json; charset=utf-8')
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": "访问令牌无效"}).encode('utf-8'))
                    return
                
                name = data.get('name', '')
                url = data.get('url', '')
                
                if not name or not url:
                    self.send_response(400)
                    self.send_header('Content-type', 'application/json; charset=utf-8')
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": "缺少名称或URL"}).encode('utf-8'))
                    return
                
                # 添加订阅
                result = add_subscription(name, url)
                
                if result:
                    self.send_response(200)
                    self.send_header('Content-type', 'application/json; charset=utf-8')
                    self.send_header('Access-Control-Allow-Origin', '*')
                    self.end_headers()
                    self.wfile.write(json.dumps({
                        "success": True,
                        "message": "订阅添加成功"
                    }).encode('utf-8'))
                else:
                    self.send_response(500)
                    self.send_header('Content-type', 'application/json; charset=utf-8')
                    self.end_headers()
                    self.wfile.write(json.dumps({
                        "error": "添加订阅失败"
                    }).encode('utf-8'))
                return
                
            # 删除订阅API
            if parsed_path.path == '/api/delete':
                access_token = load_access_token()
                client_token = data.get('token', '')
                
                if client_token != access_token:
                    self.send_response(403)
                    self.send_header('Content-type', 'application/json; charset=utf-8')
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": "访问令牌无效"}).encode('utf-8'))
                    return
                
                index = data.get('index')
                if index is None:
                    self.send_response(400)
                    self.send_header('Content-type', 'application/json; charset=utf-8')
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": "缺少索引参数"}).encode('utf-8'))
                    return
                
                # 删除订阅
                result = remove_subscription(int(index))
                
                if result:
                    self.send_response(200)
                    self.send_header('Content-type', 'application/json; charset=utf-8')
                    self.send_header('Access-Control-Allow-Origin', '*')
                    self.end_headers()
                    self.wfile.write(json.dumps({
                        "success": True,
                        "message": "订阅删除成功"
                    }).encode('utf-8'))
                else:
                    self.send_response(500)
                    self.send_header('Content-type', 'application/json; charset=utf-8')
                    self.end_headers()
                    self.wfile.write(json.dumps({
                        "error": "删除订阅失败"
                    }).encode('utf-8'))
                return
                
            # 其他路径返回404
            self.send_response(404)
            self.send_header('Content-type', 'application/json; charset=utf-8')
            self.end_headers()
            self.wfile.write(json.dumps({"error": "路径不存在"}).encode('utf-8'))
            
        except Exception as e:
            logger.error(f"处理POST请求出错: {e}")
            self.send_response(500)
            self.send_header('Content-type', 'application/json; charset=utf-8')
            self.end_headers()
            self.wfile.write(json.dumps({"error": "服务器内部错误"}).encode('utf-8'))
    
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

# 启动HTTP服务器
def run_server(port):
    server_address = ('', port)
    httpd = HTTPServer(server_address, SubRequestHandler)
    logger.info(f"HTTP服务器正在端口 {port} 上运行...")
    httpd.serve_forever()

# 启动服务器线程
def start_server_thread(port):
    server_thread = threading.Thread(target=run_server, args=(port,))
    server_thread.daemon = True
    server_thread.start()
    return server_thread

# 添加订阅
def add_subscription(name, url):
    if not name or not url:
        return False
    
    subscriptions = load_subscriptions()
    
    # 检查URL是否已存在
    for sub in subscriptions:
        if sub['url'] == url:
            logger.warning(f"订阅URL已存在: {url}")
            return False
    
    # 添加新订阅
    subscriptions.append({
        "name": name,
        "url": url,
        "added": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })
    
    # 保存更新后的订阅列表
    return save_subscriptions(subscriptions)

# 删除订阅
def remove_subscription(index):
    subscriptions = load_subscriptions()
    
    # 检查索引是否有效
    if isinstance(index, int) and 0 <= index < len(subscriptions):
        # 删除指定索引的订阅
        del subscriptions[index]
        
        # 保存更新后的订阅列表
        return save_subscriptions(subscriptions)
    else:
        logger.warning(f"无效的订阅索引: {index}")
        return False

# 列出订阅
def list_subscriptions():
    return load_subscriptions()

# 更新访问令牌
def update_access_token(token):
    return save_access_token(token)

# 更新端口
def update_port(port):
    return save_port(port)

# 保存端口
def save_port(port):
    try:
        with open(PORT_FILE, 'w') as f:
            f.write(str(port))
        return True
    except Exception as e:
        logger.error(f"保存端口配置失败: {str(e)}")
        return False

# 生成所有订阅信息
def generate_all_subscription_info():
    server_ip = get_external_ip()
    port = load_port()
    token = load_access_token()
    
    # 生成订阅链接
    subscription_links = generate_subscription_links(server_ip, port, token)
    
    # 获取订阅列表
    subscriptions = load_subscriptions()
    
    return {
        "server": server_ip,
        "port": port,
        "subscription_links": subscription_links,
        "subscriptions": subscriptions
    }

# 主函数
def main():
    parser = argparse.ArgumentParser(description='订阅聚合服务')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--start', action='store_true', help='启动服务器')
    group.add_argument('--add', nargs=2, metavar=('NAME', 'URL'), help='添加订阅')
    group.add_argument('--remove', metavar='INDEX_OR_URL', help='删除订阅')
    group.add_argument('--list', action='store_true', help='列出所有订阅')
    group.add_argument('--info', action='store_true', help='显示订阅信息')
    group.add_argument('--token', metavar='TOKEN', help='更新访问令牌')
    group.add_argument('--port', type=int, metavar='PORT', help='更新监听端口')
    
    args = parser.parse_args()
    
    # 确保目录和基本配置存在
    init_admin_credentials()
    init_users()
    
    # 处理命令行参数
    if args.start:
        port = load_port()
        # 直接启动Flask应用，而不是基本HTTP服务器
        logger.info(f"启动Flask应用，监听端口: {port}")
        app.run(host='0.0.0.0', port=port, debug=False)
            
    elif args.add:
        name, url = args.add
        if add_subscription(name, url):
            print(f"已添加订阅: {name} - {url}")
        else:
            print("添加订阅失败")
            
    elif args.remove:
        # 尝试作为索引处理
        try:
            index = int(args.remove)
            if remove_subscription(index):
                print(f"已删除订阅索引 {index}")
            else:
                print(f"删除订阅索引 {index} 失败")
        except ValueError:
            # 如果不是索引，则作为URL处理
            url_or_index = args.remove
            if remove_subscription(url_or_index):
                print(f"已删除订阅 {url_or_index}")
            else:
                print(f"删除订阅 {url_or_index} 失败")
                
    elif args.list:
        subscriptions = list_subscriptions()
        if subscriptions:
            print("订阅列表:")
            for i, sub in enumerate(subscriptions):
                print(f"{i}. {sub['name']} - {sub['url']}")
        else:
            print("没有订阅")
            
    elif args.info:
        info = generate_all_subscription_info()
        print(f"服务器: {info['server']}")
        print(f"端口: {info['port']}")
        print("\n订阅链接:")
        for client, link in info['subscription_links'].items():
            print(f"{client}: {link}")
        print("\n订阅列表:")
        for i, sub in enumerate(info['subscriptions']):
            print(f"{i}. {sub['name']} - {sub['url']}")
            
    elif args.token:
        if update_access_token(args.token):
            print(f"已更新访问令牌: {args.token}")
        else:
            print("更新访问令牌失败")
            
    elif args.port:
        if save_port(args.port):
            print(f"已更新端口: {args.port}")
        else:
            print("更新端口失败")
            
    else:
        parser.print_help()

# 初始化Flask会话管理
def init_session_management(app):
    try:
        from flask_session import Session
        app.config['SESSION_TYPE'] = 'filesystem'
        app.config['SESSION_FILE_DIR'] = '/opt/sub_merger/flask_sessions'
        app.config['SESSION_PERMANENT'] = True
        app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)  # 会话有时间期限
        Session(app)
        logger.info("Flask会话管理初始化成功")
    except ImportError:
        logger.warning("flask_session包不可用，使用默认的cookie会话")
        # 使用默认的基于cookie的会话
        app.config['SESSION_COOKIE_SECURE'] = False  # 非https环境设置为False
        app.config['SESSION_COOKIE_HTTPONLY'] = True  # 防止JavaScript访问
        app.config['SESSION_COOKIE_SAMESITE'] = None  # 允许跨站点请求
        app.config['SESSION_COOKIE_PATH'] = '/'
        app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)  # 会话有时间期限
    except Exception as e:
        logger.error(f"初始化Flask会话时出错: {str(e)}")
        # 使用基本的cookie配置
        app.config['SESSION_COOKIE_PATH'] = '/'
        app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)

# 在app初始化之后注册蓝图
app = Flask(__name__)
# 配置安全的密钥
app.secret_key = os.environ.get('SECRET_KEY', 'your_secure_secret_key_change_in_production')
# 初始化会话管理
init_session_management(app)
# 注册蓝图
app.register_blueprint(auth_api, url_prefix='/auth')

# 添加现有认证方案与新认证方案的兼容性
# 在订阅处理函数中增加API密钥认证支持
@app.route('/sub', methods=['GET'])
def get_subscription():
    try:
        # 支持新的API密钥认证
        api_key = request.args.get('api_key')
        if api_key:
            user_manager = UserManager()
            user_result = user_manager.get_user_by_api_key(api_key)
            if user_result["success"]:
                # 使用用户ID获取订阅
                user_id = user_result["user_id"]
                sub_manager = SubscriptionManager()
                subscriptions = sub_manager.get_subscriptions(user_id)
                
                if not subscriptions["success"] or not subscriptions["subscriptions"]:
                    return "未配置订阅源", 404
                
                # 处理订阅并返回
                # 收集订阅URL
                subscription_urls = [s["url"] for s in subscriptions["subscriptions"] if s["active"]]
                
                if not subscription_urls:
                    return "无可用订阅源", 404
                    
                # 合并订阅
                try:
                    merged_content = merge_subscriptions(subscription_urls)
                    # 转换为客户端格式
                    target = request.args.get('target', 'clash')
                    final_content = convert_to_client_format(merged_content, target)
                    return final_content
                except Exception as e:
                    logger.error(f"合并订阅失败: {str(e)}")
                    return f"合并订阅失败: {str(e)}", 500
        
        # 向后兼容旧的令牌认证
        token = request.args.get('token')
        access_token = load_access_token()
        
        if token != access_token:
            logger.warning(f"无效的访问令牌: {token}")
            return "无效的访问令牌", 403
            
        # 获取所有订阅
        subscriptions = load_subscriptions()
        subscription_urls = [sub["url"] for sub in subscriptions]
        
        if not subscription_urls:
            return "未配置订阅源", 404
            
        # 合并订阅
        try:
            merged_content = merge_subscriptions(subscription_urls)
            # 转换为客户端格式
            target = request.args.get('target', 'clash')
            final_content = convert_to_client_format(merged_content, target)
            return final_content
        except Exception as e:
            logger.error(f"合并订阅失败: {str(e)}")
            return f"合并订阅失败: {str(e)}", 500
            
    except Exception as e:
        logger.error(f"处理订阅请求出错: {str(e)}")
        return f"处理订阅请求出错: {str(e)}", 500

# 添加主页重定向到登录页面
@app.route('/', methods=['GET'])
def index():
    return redirect('/auth/login.html')

# 添加静态HTML页面路由
@app.route('/auth/login.html', methods=['GET'])
def login_page():
    return render_template('login.html')

@app.route('/auth/register.html', methods=['GET'])
def register_page():
    return render_template('register.html')

@app.route('/auth/dashboard.html', methods=['GET'])
def dashboard_page():
    return render_template('dashboard.html')

if __name__ == "__main__":
    # 直接调用main函数处理命令行参数
    main()