@echo off
echo ===== Starting Subscription Service Cookie Fix Deployment =====
echo.

REM Read configuration from config.ini file
echo Loading configuration from config.ini...
set REMOTE_SERVER=
set REMOTE_USER=
set REMOTE_DIR=
set SSH_KEY=

for /f "tokens=1,* delims==" %%a in ('type config.ini ^| findstr /v "^;" ^| findstr /v "^\["') do (
    set %%a=%%b
)

REM Display loaded configuration
echo Configuration loaded:
echo Server: %REMOTE_SERVER%
echo User: %REMOTE_USER%
echo Directory: %REMOTE_DIR%
echo SSH Key: %SSH_KEY%
echo.

REM Connect to VPS and deploy
echo 1. Connecting to VPS and deploying cookie fixes...

REM Copy updated files to remote server using SCP
echo 1.1 Copying updated files to remote server...
scp -i "%SSH_KEY%" -r ./app %REMOTE_USER%@%REMOTE_SERVER%:%REMOTE_DIR%/
scp -i "%SSH_KEY%" -r ./nginx %REMOTE_USER%@%REMOTE_SERVER%:%REMOTE_DIR%/

REM Stop and remove containers
echo 1.2 Stopping previous containers...
ssh -i "%SSH_KEY%" %REMOTE_USER%@%REMOTE_SERVER% "cd %REMOTE_DIR% && docker-compose down"

REM Start with forced rebuild
echo 1.3 Building and starting Docker containers...
ssh -i "%SSH_KEY%" %REMOTE_USER%@%REMOTE_SERVER% "cd %REMOTE_DIR% && docker-compose up -d --build"

REM Check service status
echo 2. Checking service status...
ssh -i "%SSH_KEY%" %REMOTE_USER%@%REMOTE_SERVER% "cd %REMOTE_DIR% && docker-compose ps"

echo.
echo 3. Cookie fix deployment complete! To test:
echo   1. Open browser and test login at http://%REMOTE_SERVER%:8080/auth/login.html
echo   2. After login, check if you can access the dashboard 
echo   3. If still having issues, check cookies with debug endpoint: http://%REMOTE_SERVER%:8080/auth/debug/cookies
echo.
echo ===== Cookie Fix Deployment completed! =====
echo Press any key to exit...
pause > nul