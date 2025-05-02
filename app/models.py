import sqlite3
import os
import json
import time
import uuid
import hashlib
import secrets
from datetime import datetime, timedelta

# 数据库初始化
class Database:
    def __init__(self, db_path="/opt/sub_merger/users.db"):
        self.db_path = db_path
        self.init_db()
    
    def get_connection(self):
        return sqlite3.connect(self.db_path)
    
    def init_db(self):
        # 确保目录存在
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        # 创建表
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # 用户表
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                email TEXT UNIQUE,
                role TEXT DEFAULT 'user',
                api_key TEXT UNIQUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                is_active BOOLEAN DEFAULT 1
            )
            ''')
            
            # 会话表
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                ip_address TEXT,
                user_agent TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
            ''')
            
            # 订阅源表
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS subscription_sources (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                url TEXT NOT NULL,
                user_id INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_updated TIMESTAMP,
                is_active BOOLEAN DEFAULT 1,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
            ''')
            
            # 初始化管理员账户
            admin_exists = cursor.execute("SELECT id FROM users WHERE username = 'admin'").fetchone()
            if not admin_exists:
                admin_password = os.environ.get('ADMIN_PASSWORD', 'your_secure_password')
                admin_password_hash = self._hash_password(admin_password)
                admin_api_key = secrets.token_hex(16)
                cursor.execute(
                    "INSERT INTO users (username, password_hash, role, api_key) VALUES (?, ?, ?, ?)",
                    ('admin', admin_password_hash, 'admin', admin_api_key)
                )
    
    def _hash_password(self, password):
        # 使用 SHA-256 哈希算法和随机盐值
        salt = uuid.uuid4().hex
        return hashlib.sha256(salt.encode() + password.encode()).hexdigest() + ':' + salt
    
    def check_password(self, hashed_password, user_password):
        password, salt = hashed_password.split(':')
        return password == hashlib.sha256(salt.encode() + user_password.encode()).hexdigest()


# 用户管理类
class UserManager:
    def __init__(self):
        self.db = Database()
    
    def register_user(self, username, password, email=None):
        try:
            conn = self.db.get_connection()
            cursor = conn.cursor()
            
            # 检查用户名是否已存在
            if cursor.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone():
                return {"success": False, "message": "用户名已存在"}
            
            # 检查邮箱是否已存在
            if email and cursor.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone():
                return {"success": False, "message": "邮箱已被使用"}
            
            # 哈希密码
            password_hash = self.db._hash_password(password)
            
            # 生成API密钥
            api_key = secrets.token_hex(16)
            
            # 插入用户记录
            cursor.execute(
                "INSERT INTO users (username, password_hash, email, api_key) VALUES (?, ?, ?, ?)",
                (username, password_hash, email, api_key)
            )
            conn.commit()
            
            return {"success": True, "message": "注册成功", "api_key": api_key}
        except Exception as e:
            return {"success": False, "message": f"注册失败: {str(e)}"}
        finally:
            if conn:
                conn.close()
    
    def authenticate_user(self, username, password):
        try:
            conn = self.db.get_connection()
            cursor = conn.cursor()
            
            # 获取用户信息
            user = cursor.execute(
                "SELECT id, username, password_hash, role, api_key FROM users WHERE username = ? AND is_active = 1", 
                (username,)
            ).fetchone()
            
            if not user:
                return {"success": False, "message": "用户不存在或已被禁用"}
            
            # 验证密码
            if not self.db.check_password(user[2], password):
                return {"success": False, "message": "密码错误"}
            
            # 更新最后登录时间
            cursor.execute(
                "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?",
                (user[0],)
            )
            
            # 创建会话
            session_id = secrets.token_hex(16)
            expires_at = datetime.now() + timedelta(days=7)
            
            cursor.execute(
                "INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)",
                (session_id, user[0], expires_at)
            )
            
            conn.commit()
            
            return {
                "success": True,
                "message": "登录成功",
                "user_id": user[0],
                "username": user[1],
                "role": user[3],
                "api_key": user[4],
                "session_id": session_id
            }
        except Exception as e:
            return {"success": False, "message": f"登录失败: {str(e)}"}
        finally:
            if conn:
                conn.close()
    
    def validate_session(self, session_id):
        try:
            conn = self.db.get_connection()
            cursor = conn.cursor()
            
            # 获取会话信息
            session = cursor.execute(
                "SELECT user_id, expires_at FROM sessions WHERE id = ?", 
                (session_id,)
            ).fetchone()
            
            if not session:
                return {"success": False, "message": "会话不存在"}
            
            # 检查会话是否过期
            expires_at = datetime.strptime(session[1], "%Y-%m-%d %H:%M:%S")
            if expires_at < datetime.now():
                return {"success": False, "message": "会话已过期"}
            
            # 获取用户信息
            user = cursor.execute(
                "SELECT id, username, role, api_key FROM users WHERE id = ? AND is_active = 1", 
                (session[0],)
            ).fetchone()
            
            if not user:
                return {"success": False, "message": "用户不存在或已被禁用"}
            
            return {
                "success": True,
                "user_id": user[0],
                "username": user[1],
                "role": user[2],
                "api_key": user[3]
            }
        except Exception as e:
            return {"success": False, "message": f"验证失败: {str(e)}"}
        finally:
            if conn:
                conn.close()
    
    def logout(self, session_id):
        try:
            conn = self.db.get_connection()
            cursor = conn.cursor()
            
            # 删除会话
            cursor.execute("DELETE FROM sessions WHERE id = ?", (session_id,))
            conn.commit()
            
            return {"success": True, "message": "注销成功"}
        except Exception as e:
            return {"success": False, "message": f"注销失败: {str(e)}"}
        finally:
            if conn:
                conn.close()
    
    def get_user_by_api_key(self, api_key):
        try:
            conn = self.db.get_connection()
            cursor = conn.cursor()
            
            # 获取用户信息
            user = cursor.execute(
                "SELECT id, username, role FROM users WHERE api_key = ? AND is_active = 1", 
                (api_key,)
            ).fetchone()
            
            if not user:
                return {"success": False, "message": "API密钥无效或用户已被禁用"}
            
            return {
                "success": True,
                "user_id": user[0],
                "username": user[1],
                "role": user[2]
            }
        except Exception as e:
            return {"success": False, "message": f"验证失败: {str(e)}"}
        finally:
            if conn:
                conn.close()

# 订阅源管理类
class SubscriptionManager:
    def __init__(self):
        self.db = Database()
    
    def add_subscription(self, name, url, user_id):
        try:
            conn = self.db.get_connection()
            cursor = conn.cursor()
            
            # 检查订阅名是否已存在
            existing = cursor.execute(
                "SELECT id FROM subscription_sources WHERE name = ? AND user_id = ?", 
                (name, user_id)
            ).fetchone()
            
            if existing:
                return {"success": False, "message": "订阅名称已存在"}
            
            # 插入订阅源
            cursor.execute(
                "INSERT INTO subscription_sources (name, url, user_id) VALUES (?, ?, ?)",
                (name, url, user_id)
            )
            conn.commit()
            
            return {"success": True, "message": "订阅源添加成功"}
        except Exception as e:
            return {"success": False, "message": f"添加失败: {str(e)}"}
        finally:
            if conn:
                conn.close()
    
    def delete_subscription(self, subscription_id, user_id):
        try:
            conn = self.db.get_connection()
            cursor = conn.cursor()
            
            # 检查订阅是否存在且属于该用户
            sub = cursor.execute(
                "SELECT id FROM subscription_sources WHERE id = ? AND user_id = ?", 
                (subscription_id, user_id)
            ).fetchone()
            
            if not sub:
                return {"success": False, "message": "订阅不存在或无权删除"}
            
            # 删除订阅
            cursor.execute("DELETE FROM subscription_sources WHERE id = ?", (subscription_id,))
            conn.commit()
            
            return {"success": True, "message": "订阅删除成功"}
        except Exception as e:
            return {"success": False, "message": f"删除失败: {str(e)}"}
        finally:
            if conn:
                conn.close()
    
    def get_subscriptions(self, user_id):
        try:
            conn = self.db.get_connection()
            cursor = conn.cursor()
            
            # 获取用户的所有订阅
            subs = cursor.execute(
                "SELECT id, name, url, created_at, last_updated, is_active FROM subscription_sources WHERE user_id = ?", 
                (user_id,)
            ).fetchall()
            
            result = []
            for sub in subs:
                result.append({
                    "id": sub[0],
                    "name": sub[1],
                    "url": sub[2],
                    "created_at": sub[3],
                    "last_updated": sub[4],
                    "is_active": bool(sub[5])
                })
            
            return {"success": True, "subscriptions": result}
        except Exception as e:
            return {"success": False, "message": f"获取失败: {str(e)}"}
        finally:
            if conn:
                conn.close()
    
    def update_subscription_status(self, subscription_id, user_id, is_active):
        try:
            conn = self.db.get_connection()
            cursor = conn.cursor()
            
            # 检查订阅是否存在且属于该用户
            sub = cursor.execute(
                "SELECT id FROM subscription_sources WHERE id = ? AND user_id = ?", 
                (subscription_id, user_id)
            ).fetchone()
            
            if not sub:
                return {"success": False, "message": "订阅不存在或无权操作"}
            
            # 更新订阅状态
            cursor.execute(
                "UPDATE subscription_sources SET is_active = ? WHERE id = ?", 
                (1 if is_active else 0, subscription_id)
            )
            conn.commit()
            
            return {"success": True, "message": "订阅状态更新成功"}
        except Exception as e:
            return {"success": False, "message": f"更新失败: {str(e)}"}
        finally:
            if conn:
                conn.close() 