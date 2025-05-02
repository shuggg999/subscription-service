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
        # 打印详细的请求信息便于调试
        print(f"============ 请求调试信息 开始 ============")
        print(f"请求路径: {request.path}")
        print(f"请求方法: {request.method}")
        print(f"请求来源: {request.remote_addr}")
        print(f"所有Cookie: {request.cookies}")
        print(f"请求头部: {dict(request.headers)}")
        print(f"============ 请求调试信息 结束 ============")
        
        # 从所有可能的来源尝试获取session_id
        session_id = None
        
        # 1. 从 cookie 获取
        session_id = request.cookies.get('session_id')
        if session_id:
            print(f"从所有cookie中找到session_id: {session_id}")
            
        # 2. 尝试从Authorization头获取
        if not session_id:
            auth_header = request.headers.get('Authorization')
            if auth_header and auth_header.startswith('Bearer '):
                session_id = auth_header[7:]
                print(f"从Authorization头找到session_id: {session_id}")
        
        # 3. 尝试从session获取
        if not session_id and 'session_id' in session:
            session_id = session['session_id']
            print(f"从Flask会话中找到session_id: {session_id}")
            
        if not session_id:
            print(f"警告: 未找到任何session_id! 请使用/auth/debug/cookies进行调试")
            return jsonify({"success": False, "message": "未登录或会话已过期"}), 401
        
        # 验证会话
        result = user_manager.validate_session(session_id)
        if not result["success"]:
            print(f"会话验证失败: {result.get('message', '未知错误')}, session_id: {session_id}")
            resp = make_response(jsonify({"success": False, "message": "会话已过期或无效"}), 401)
            # 在所有可能的路径上清除cookie
            resp.set_cookie('session_id', '', expires=0, path='/')
            resp.set_cookie('session_id', '', expires=0, path='/auth')
            resp.set_cookie('session_id', '', expires=0)
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
    try:
        data = request.json
        username = data.get('username')
        password = data.get('password')
        
        print(f"登录尝试: {username}")
        
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
        
        # 设置cookie，最简化配置以确保功能
        print(f"设置cookie session_id: {result['session_id']}")
        resp.set_cookie(
            'session_id', 
            result["session_id"], 
            max_age=7*24*60*60, 
            httponly=False,  # 关闭httponly以方便调试
            path='/',       # 确保全站适用
            secure=False,   # 开发环境设为False
            samesite=None   # 关闭samesite限制
        )
        
        # 同时存储到flask session
        session['session_id'] = result["session_id"]
        print(f"已将session_id存储到Flask session: {session['session_id']}")
        
        return resp
    except Exception as e:
        print(f"登录错误: {str(e)}")
        return jsonify({"success": False, "message": f"登录过程中发生错误: {str(e)}"}), 500

# 注销接口
@auth_api.route('/logout', methods=['POST'])
@login_required
def logout():
    session_id = request.cookies.get('session_id')
    result = user_manager.logout(session_id)
    
    # 清除cookie
    resp = make_response(jsonify(result))
    resp.set_cookie('session_id', '', expires=0, path='/')
    resp.set_cookie('session_id', '', expires=0, path='/auth')
    resp.set_cookie('session_id', '', expires=0)
    
    # 清除session
    if 'session_id' in session:
        session.pop('session_id')
    
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

# Cookie 调试接口
@auth_api.route('/debug/cookies', methods=['GET'])
def debug_cookies():
    cookies = {k: v for k, v in request.cookies.items()}
    headers = {k: v for k, v in request.headers.items()}
    
    # 检查是否有session_id cookie
    session_id_found = 'session_id' in cookies
    session_value = cookies.get('session_id', '(未找到)')
    
    # 返回详细信息
    return jsonify({
        "cookies": cookies,
        "headers": headers,
        "session_id_found": session_id_found,
        "session_id": session_value,
        "remote_addr": request.remote_addr,
        "host": request.host,
        "referrer": request.referrer,
        "user_agent": request.user_agent.string,
        "secure": request.is_secure,
        "flask_session": dict(session),
        "is_session_in_flask_session": 'session_id' in session
    })

# 设置测试Cookie的端点
@auth_api.route('/debug/set_test_cookie', methods=['GET'])
def set_test_cookie():
    # 创建响应
    resp = make_response(jsonify({
        "success": True,
        "message": "测试Cookie已设置"
    }))
    
    # 设置测试cookie
    resp.set_cookie(
        'test_cookie', 
        'cookie_value_' + str(int(time.time())), 
        max_age=3600,
        httponly=False,
        path='/',
        secure=False,
        samesite=None
    )
    
    return resp