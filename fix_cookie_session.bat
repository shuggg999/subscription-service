@echo off
echo ===== 会话Cookie问题修复脚本 =====
echo.

REM 读取配置文件
echo 1. 读取配置信息...
set REMOTE_SERVER=
set REMOTE_USER=
set REMOTE_DIR=
set SSH_KEY=

for /f "tokens=1,* delims==" %%a in ('type config.ini ^| findstr /v "^;" ^| findstr /v "^\["') do (
    set %%a=%%b
)

REM 显示配置信息
echo 配置信息:
echo 服务器: %REMOTE_SERVER%
echo 用户: %REMOTE_USER%
echo 目录: %REMOTE_DIR%
echo SSH密钥: %SSH_KEY%
echo.

echo 2. 复制修改后的文件到VPS...
echo 2.1 复制app/auth_api.py...
scp -i "%SSH_KEY%" "app\auth_api.py" %REMOTE_USER%@%REMOTE_SERVER%:%REMOTE_DIR%/app/

echo 2.2 复制app/subscription_service.py...
scp -i "%SSH_KEY%" "app\subscription_service.py" %REMOTE_USER%@%REMOTE_SERVER%:%REMOTE_DIR%/app/

echo 2.3 复制nginx/conf/default.conf...
scp -i "%SSH_KEY%" "nginx\conf\default.conf" %REMOTE_USER%@%REMOTE_SERVER%:%REMOTE_DIR%/nginx/conf/

echo 2.4 复制nginx/html/cookie_test.html...
scp -i "%SSH_KEY%" "nginx\html\cookie_test.html" %REMOTE_USER%@%REMOTE_SERVER%:%REMOTE_DIR%/nginx/html/

echo 3. 重启Docker容器...
ssh -i "%SSH_KEY%" %REMOTE_USER%@%REMOTE_SERVER% "cd %REMOTE_DIR% && docker-compose down && docker-compose up -d --build"

echo 4. 查看容器状态...
ssh -i "%SSH_KEY%" %REMOTE_USER%@%REMOTE_SERVER% "cd %REMOTE_DIR% && docker-compose ps"

echo.
echo 5. 修复完成！测试步骤:
echo   1. 清除浏览器Cookie后访问: http://%REMOTE_SERVER%:8080/auth/login.html
echo   2. 使用您的账户登录
echo   3. 检查是否成功进入仪表盘
echo   4. 如果仍有问题，访问调试端点: http://%REMOTE_SERVER%:8080/auth/debug/cookies
echo   5. 检查Cookie测试端点: http://%REMOTE_SERVER%:8080/auth/debug/set_test_cookie
echo   6. 或者使用Cookie测试页面: http://%REMOTE_SERVER%:8080/cookie_test.html
echo.
echo ===== 修复脚本执行完毕 =====
pause