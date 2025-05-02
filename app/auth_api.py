import os
import json
import time
from flask import Blueprint, request, jsonify, session, make_response
from functools import wraps
from models import UserManager, SubscriptionManager

auth_api = Blueprint('auth_api', __name__)
user_manager = UserManager()
subscription_manager = SubscriptionManager()

# 用户会话中间件
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        session_id = request.cookies.get('session_id')
        if not session_id:
            return jsonify({"success": False, "message": "未登录"}), 401
        
        # 验证会话
        result = user_manager.validate_session(session_id)
        if not result["success"]:
            resp = make_response(jsonify({"success": False, "message": "会话已过期或无效"}), 401)
            resp.set_cookie('session_id', '', expires=0)  # 清除无效的cookie
            return resp
        
        # 将用户信息添加到请求中
        request.user = {
            "user_id": result["user_id"],
            "username": result["username"],
            "role": result["role"],
            "api_key": result["api_key"]
        }
        
        return f(*args, **kwargs)
    return decorated_function

# 管理员权限中间件
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        session_id = request.cookies.get('session_id')
        if not session_id:
            return jsonify({"success": False, "message": "未登录"}), 401
        
        # 验证会话
        result = user_manager.validate_session(session_id)
        if not result["success"]:
            resp = make_response(jsonify({"success": False, "message": "会话已过期或无效"}), 401)
            resp.set_cookie('session_id', '', expires=0)
            return resp
        
        # 检查管理员权限
        if result["role"] != "admin":
            return jsonify({"success": False, "message": "需要管理员权限"}), 403
        
        # 将用户信息添加到请求中
        request.user = {
            "user_id": result["user_id"],
            "username": result["username"],
            "role": result["role"],
            "api_key": result["api_key"]
        }
        
        return f(*args, **kwargs)
    return decorated_function

# API密钥验证中间件
def api_key_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.args.get('api_key') or request.headers.get('X-API-Key')
        if not api_key:
            return jsonify({"success": False, "message": "缺少API密钥"}), 401
        
        # 验证API密钥
        result = user_manager.get_user_by_api_key(api_key)
        if not result["success"]:
            return jsonify({"success": False, "message": "API密钥无效"}), 401
        
        # 将用户信息添加到请求中
        request.user = {
            "user_id": result["user_id"],
            "username": result["username"],
            "role": result["role"]
        }
        
        return f(*args, **kwargs)
    return decorated_function

# 注册接口
@auth_api.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')
    
    if not username or not password:
        return jsonify({"success": False, "message": "用户名和密码不能为空"}), 400
    
    result = user_manager.register_user(username, password, email)
    
    if not result["success"]:
        return jsonify(result), 400
    
    return jsonify(result), 201

# 登录接口
@auth_api.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({"success": False, "message": "用户名和密码不能为空"}), 400
    
    result = user_manager.authenticate_user(username, password)
    
    if not result["success"]:
        return jsonify(result), 401
    
    # 创建带会话ID的响应
    resp = make_response(jsonify({
        "success": True,
        "message": "登录成功",
        "username": result["username"],
        "role": result["role"],
        "api_key": result["api_key"]
    }))
    
    # 设置cookie，7天过期
    resp.set_cookie(
        'session_id', 
        result["session_id"], 
        max_age=7*24*60*60, 
        httponly=True,
        secure=request.is_secure,  # 在HTTPS时设为True
        samesite='Lax'
    )
    
    return resp

# 注销接口
@auth_api.route('/logout', methods=['POST'])
@login_required
def logout():
    session_id = request.cookies.get('session_id')
    result = user_manager.logout(session_id)
    
    # 清除cookie
    resp = make_response(jsonify(result))
    resp.set_cookie('session_id', '', expires=0)
    
    return resp

# 获取当前用户信息
@auth_api.route('/me', methods=['GET'])
@login_required
def get_me():
    return jsonify({
        "success": True,
        "user": {
            "user_id": request.user["user_id"],
            "username": request.user["username"],
            "role": request.user["role"],
            "api_key": request.user["api_key"]
        }
    })

# 订阅源管理接口
@auth_api.route('/subscriptions', methods=['GET'])
@login_required
def get_subscriptions():
    user_id = request.user["user_id"]
    result = subscription_manager.get_subscriptions(user_id)
    return jsonify(result)

@auth_api.route('/subscriptions', methods=['POST'])
@login_required
def add_subscription():
    user_id = request.user["user_id"]
    data = request.json
    name = data.get('name')
    url = data.get('url')
    
    if not name or not url:
        return jsonify({"success": False, "message": "名称和URL不能为空"}), 400
    
    result = subscription_manager.add_subscription(name, url, user_id)
    
    if not result["success"]:
        return jsonify(result), 400
    
    return jsonify(result), 201

@auth_api.route('/subscriptions/<int:subscription_id>', methods=['DELETE'])
@login_required
def delete_subscription(subscription_id):
    user_id = request.user["user_id"]
    result = subscription_manager.delete_subscription(subscription_id, user_id)
    
    if not result["success"]:
        return jsonify(result), 400
    
    return jsonify(result)

@auth_api.route('/subscriptions/<int:subscription_id>/status', methods=['PUT'])
@login_required
def update_subscription_status(subscription_id):
    user_id = request.user["user_id"]
    data = request.json
    is_active = data.get('is_active', True)
    
    result = subscription_manager.update_subscription_status(subscription_id, user_id, is_active)
    
    if not result["success"]:
        return jsonify(result), 400
    
    return jsonify(result)

# API密钥访问的订阅接口
@auth_api.route('/api/subscriptions', methods=['GET'])
@api_key_required
def api_get_subscriptions():
    user_id = request.user["user_id"]
    result = subscription_manager.get_subscriptions(user_id)
    return jsonify(result)

# 生成订阅链接
@auth_api.route('/generate_subscription_link', methods=['GET'])
@login_required
def generate_subscription_link():
    user_id = request.user["user_id"]
    api_key = request.user["api_key"]
    client_type = request.args.get('client_type', 'v2ray')
    
    # 构建订阅链接
    base_url = request.host_url.rstrip('/')
    subscription_url = f"{base_url}/sub?api_key={api_key}&target={client_type}"
    
    return jsonify({
        "success": True,
        "subscription_url": subscription_url
    })

# 服务间通信API - 获取订阅数据
@auth_api.route('/api/service/subscriptions', methods=['GET'])
def service_get_subscriptions():
    api_key = request.headers.get('X-Service-Key')
    service_token = os.environ.get('SERVICE_COMMUNICATION_TOKEN')
    
    # 验证服务通信令牌
    if not api_key or api_key != service_token:
        return jsonify({"success": False, "message": "服务认证失败"}), 401
    
    user_id = request.args.get('user_id')
    if not user_id:
        return jsonify({"success": False, "message": "缺少用户ID参数"}), 400
    
    # 获取订阅数据
    result = subscription_manager.get_subscriptions(user_id)
    return jsonify(result)

# 健康检查接口
@auth_api.route('/health', methods=['GET'])
def health_check():
    return jsonify({"status": "ok", "timestamp": int(time.time())}) 