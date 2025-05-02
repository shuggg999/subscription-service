@echo off
echo ===== 修复会话Cookie问题 =====

echo 1. 修改auth_api.py文件...
echo 2. 修改login方法中的Cookie设置...

cd %~dp0
copy /y app\auth_api.py app\auth_api.py.backup

echo 修改内容应用中...
