import os
import json
import time
import logging
from flask import Blueprint, request, jsonify, session, make_response, redirect
from functools import wraps
from models import UserManager, SubscriptionManager

# 配置详细日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("AuthAPI")

auth_api = Blueprint('auth_api', __name__)
user_manager = UserManager()
subscription_manager = SubscriptionManager()

# 用户会话中间件 - 超详细日志版
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        logger.info(f"===== 访问受保护资源: {request.path} =====")
        logger.info(f"请求方法: {request.method}")
        logger.info(f"客户端IP: {request.remote_addr}")
        logger.info(f"所有Cookie: {request.cookies}")
        logger.info(f"请求头: {dict(request.headers)}")
        logger.info(f"Flask Session内容: {dict(session) if session else '{}'}")
        
        # 检查会话是否有效
        user_id = session.get('user_id')
        
        if not user_id:
            logger.warning("会话中没有user_id，需要重新登录")
            return jsonify({"success": False, "message": "请先登录"}), 401
        
        # 查询用户信息
        try:
            user_info = user_manager.get_user_by_id(user_id)
            
            if not user_info["success"]:
                logger.warning(f"无法获取用户信息: {user_info.get('message')}")
                # 清除无效会话
                session.clear()
                return jsonify({"success": False, "message": "会话已过期，请重新登录"}), 401
            
            # 用户有效，将信息添加到请求
            request.user = {
                "user_id": user_info["user_id"],
                "username": user_info["username"],
                "role": user_info["role"],
                "api_key": user_info["api_key"]
            }
            
            logger.info(f"用户已验证: {user_info['username']} (ID: {user_info['user_id']})")
            return f(*args, **kwargs)
            
        except Exception as e:
            logger.error(f"验证会话时出错: {str(e)}")
            session.clear()
            return jsonify({"success": False, "message": f"验证会话时出错: {str(e)}"}), 500
    
    return decorated_function

# 管理员权限中间件
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        logger.info(f"===== 访问管理员资源: {request.path} =====")
        
        user_id = session.get('user_id')
        if not user_id:
            logger.warning("会话中没有user_id，需要管理员权限")
            return jsonify({"success": False, "message": "请先登录"}), 401
        
        # 查询用户信息
        try:
            user_info = user_manager.get_user_by_id(user_id)
            
            if not user_info["success"]:
                logger.warning(f"无法获取用户信息: {user_info.get('message')}")
                session.clear()
                return jsonify({"success": False, "message": "会话已过期，请重新登录"}), 401
            
            # 检查管理员权限
            if user_info["role"] != "admin":
                logger.warning(f"用户 {user_info['username']} 不是管理员")
                return jsonify({"success": False, "message": "需要管理员权限"}), 403
            
            # 用户有效，将信息添加到请求
            request.user = {
                "user_id": user_info["user_id"],
                "username": user_info["username"],
                "role": user_info["role"],
                "api_key": user_info["api_key"]
            }
            
            logger.info(f"管理员已验证: {user_info['username']}")
            return f(*args, **kwargs)
            
        except Exception as e:
            logger.error(f"验证管理员权限时出错: {str(e)}")
            return jsonify({"success": False, "message": f"验证管理员权限时出错: {str(e)}"}), 500
    
    return decorated_function

# API密钥验证中间件
def api_key_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.args.get('api_key') or request.headers.get('X-API-Key')
        
        if not api_key:
            logger.warning("API请求缺少密钥")
            return jsonify({"success": False, "message": "缺少API密钥"}), 401
        
        # 验证API密钥
        result = user_manager.get_user_by_api_key(api_key)
        if not result["success"]:
            logger.warning(f"API密钥无效: {api_key[:8]}...")
            return jsonify({"success": False, "message": "API密钥无效"}), 401
        
        # 将用户信息添加到请求中
        request.user = {
            "user_id": result["user_id"],
            "username": result["username"],
            "role": result["role"]
        }
        
        logger.info(f"API请求已验证，用户: {result['username']}")
        return f(*args, **kwargs)
    
    return decorated_function

# 注册接口
@auth_api.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')
    
    logger.info(f"注册请求: 用户名={username}, 邮箱={email}")
    
    if not username or not password:
        logger.warning("注册失败: 用户名或密码为空")
        return jsonify({"success": False, "message": "用户名和密码不能为空"}), 400
    
    result = user_manager.register_user(username, password, email)
    
    if not result["success"]:
        logger.warning(f"注册失败: {result.get('message')}")
        return jsonify(result), 400
    
    logger.info(f"注册成功: 用户名={username}")
    return jsonify(result), 201

# 登录接口
@auth_api.route('/login', methods=['POST'])
def login():
    try:
        logger.info("="*50)
        logger.info(f"登录请求开始, 请求IP: {request.remote_addr}")
        logger.info(f"请求头: {dict(request.headers)}")
        
        data = request.json
        username = data.get('username')
        password = data.get('password')
        
        logger.info(f"登录尝试: 用户名={username}")
        
        if not username or not password:
            logger.warning("登录失败: 用户名或密码为空")
            return jsonify({"success": False, "message": "用户名和密码不能为空"}), 400
        
        result = user_manager.authenticate_user(username, password)
        
        if not result["success"]:
            logger.warning(f"登录失败: {result.get('message')}")
            return jsonify(result), 401
        
        # 将用户信息保存到Flask会话
        session.permanent = True
        session['user_id'] = result["user_id"]
        session['username'] = result["username"]
        session['role'] = result["role"]
        
        # 创建带会话信息的响应
        resp_data = {
            "success": True,
            "message": "登录成功",
            "username": result["username"],
            "role": result["role"],
            "api_key": result["api_key"]
        }
        
        logger.info(f"登录成功: 用户={username}, ID={result['user_id']}")
        logger.info(f"会话已设置: {dict(session)}")
        logger.info(f"返回数据: {resp_data}")
        logger.info("="*50)
        
        return jsonify(resp_data)
    
    except Exception as e:
        logger.error(f"登录过程出错: {str(e)}", exc_info=True)
        return jsonify({"success": False, "message": f"登录过程中发生错误: {str(e)}"}), 500

# 注销接口
@auth_api.route('/logout', methods=['POST'])
def logout():
    logger.info(f"注销请求, 用户: {session.get('username', '未知')}")
    
    # 清除会话
    session.clear()
    
    logger.info("会话已清除")
    return jsonify({"success": True, "message": "已成功注销"})

# 获取当前用户信息
@auth_api.route('/me', methods=['GET'])
@login_required
def get_me():
    logger.info("="*50)
    logger.info(f"获取用户信息请求, IP: {request.remote_addr}")
    logger.info(f"会话内容: {dict(session)}")
    logger.info(f"请求Cookie: {request.cookies}")
    
    user_data = {
        "user_id": request.user["user_id"],
        "username": request.user["username"],
        "role": request.user["role"],
        "api_key": request.user["api_key"]
    }
    
    logger.info(f"返回用户信息: {user_data}")
    logger.info("="*50)
    
    return jsonify({
        "success": True,
        "user": user_data
    })

# 订阅源管理接口
@auth_api.route('/subscriptions', methods=['GET'])
@login_required
def get_subscriptions():
    user_id = request.user["user_id"]
    logger.info(f"获取订阅列表, 用户ID: {user_id}")
    
    result = subscription_manager.get_subscriptions(user_id)
    return jsonify(result)

@auth_api.route('/subscriptions', methods=['POST'])
@login_required
def add_subscription():
    user_id = request.user["user_id"]
    data = request.json
    name = data.get('name')
    url = data.get('url')
    
    logger.info(f"添加订阅请求, 用户ID: {user_id}, 名称: {name}")
    
    if not name or not url:
        logger.warning("添加订阅失败: 名称或URL为空")
        return jsonify({"success": False, "message": "名称和URL不能为空"}), 400
    
    result = subscription_manager.add_subscription(name, url, user_id)
    
    if not result["success"]:
        logger.warning(f"添加订阅失败: {result.get('message')}")
        return jsonify(result), 400
    
    logger.info(f"添加订阅成功: {name}")
    return jsonify(result), 201

@auth_api.route('/subscriptions/<int:subscription_id>', methods=['DELETE'])
@login_required
def delete_subscription(subscription_id):
    user_id = request.user["user_id"]
    logger.info(f"删除订阅请求, 用户ID: {user_id}, 订阅ID: {subscription_id}")
    
    result = subscription_manager.delete_subscription(subscription_id, user_id)
    
    if not result["success"]:
        logger.warning(f"删除订阅失败: {result.get('message')}")
        return jsonify(result), 400
    
    logger.info(f"删除订阅成功: ID={subscription_id}")
    return jsonify(result)

@auth_api.route('/subscriptions/<int:subscription_id>/status', methods=['PUT'])
@login_required
def update_subscription_status(subscription_id):
    user_id = request.user["user_id"]
    data = request.json
    is_active = data.get('is_active', True)
    
    logger.info(f"更新订阅状态, 用户ID: {user_id}, 订阅ID: {subscription_id}, 状态: {is_active}")
    
    result = subscription_manager.update_subscription_status(subscription_id, user_id, is_active)
    
    if not result["success"]:
        logger.warning(f"更新订阅状态失败: {result.get('message')}")
        return jsonify(result), 400
    
    logger.info(f"更新订阅状态成功: ID={subscription_id}, 状态={is_active}")
    return jsonify(result)

# API密钥访问的订阅接口
@auth_api.route('/api/subscriptions', methods=['GET'])
@api_key_required
def api_get_subscriptions():
    user_id = request.user["user_id"]
    logger.info(f"API获取订阅列表, 用户ID: {user_id}")
    
    result = subscription_manager.get_subscriptions(user_id)
    return jsonify(result)

# 生成订阅链接
@auth_api.route('/generate_subscription_link', methods=['GET'])
@login_required
def generate_subscription_link():
    user_id = request.user["user_id"]
    api_key = request.user["api_key"]
    client_type = request.args.get('client_type', 'v2ray')
    
    logger.info(f"生成订阅链接, 用户ID: {user_id}, 客户端类型: {client_type}")
    
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
        logger.warning("服务间API调用失败: 无效的服务密钥")
        return jsonify({"success": False, "message": "服务认证失败"}), 401
    
    user_id = request.args.get('user_id')
    if not user_id:
        logger.warning("服务间API调用失败: 缺少用户ID")
        return jsonify({"success": False, "message": "缺少用户ID参数"}), 400
    
    logger.info(f"服务间获取订阅数据, 用户ID: {user_id}")
    
    # 获取订阅数据
    result = subscription_manager.get_subscriptions(user_id)
    return jsonify(result)

# 健康检查接口
@auth_api.route('/health', methods=['GET'])
def health_check():
    return jsonify({"status": "ok", "timestamp": int(time.time())})

# 会话状态检查
@auth_api.route('/debug/session', methods=['GET'])
def debug_session():
    return jsonify({
        "has_session": bool(session),
        "session_data": dict(session) if session else {},
        "cookies": {k: v for k, v in request.cookies.items()},
        "headers": {k: v for k, v in request.headers.items()},
        "server_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "remote_addr": request.remote_addr
    })

# 测试设置会话
@auth_api.route('/debug/set_session', methods=['GET'])
def set_test_session():
    test_value = request.args.get('value', f'test_{int(time.time())}')
    session['test_value'] = test_value
    
    return jsonify({
        "success": True,
        "message": "测试会话已设置",
        "session": dict(session)
    })

# 直接跳转到仪表盘(不验证)
@auth_api.route('/debug/direct_dashboard', methods=['GET'])
def direct_dashboard():
    # 创建一个测试会话
    session['user_id'] = 1  # 假设ID为1的用户存在
    session['username'] = 'test_user'
    session['role'] = 'user'
    
    logger.info(f"直接跳转到仪表盘, 会话: {dict(session)}")
    
    # 重定向到仪表盘
    return redirect('/auth/dashboard.html')
