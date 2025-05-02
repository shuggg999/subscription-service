@echo off
echo Starting to redeploy subscription service with fixes...

:: Stop existing containers
echo Stopping existing containers...
docker-compose down

:: Rebuild the containers
echo Rebuilding services...
docker-compose build

:: Start the services
echo Starting services...
docker-compose up -d

:: Show logs
echo Showing logs (press Ctrl+C to exit)...
docker-compose logs -f
@echo off
echo ===== Starting Subscription Service Deployment =====
echo.

REM Read configuration from config.ini file
echo Loading configuration from config.ini...
set REMOTE_SERVER=
set REMOTE_USER=
set REMOTE_DIR=
set SSH_KEY=
set GIT_BRANCH=

for /f "tokens=1,* delims==" %%a in ('type config.ini ^| findstr /v "^;" ^| findstr /v "^\["') do (
    set %%a=%%b
)

REM Display loaded configuration
echo Configuration loaded:
echo Server: %REMOTE_SERVER%
echo User: %REMOTE_USER%
echo Directory: %REMOTE_DIR%
echo SSH Key: %SSH_KEY%
echo Git Branch: %GIT_BRANCH%
echo.

REM Git operations
echo 1. Initializing repository if needed...

IF NOT EXIST .git (
  echo Creating new git repository...
  git init
  git add .
  git commit -m "Initial commit"
)

echo 2. Committing and pushing code to GitHub...
git add -A
IF EXIST .git\refs\remotes\origin\%GIT_BRANCH% (
  git pull origin %GIT_BRANCH%
) ELSE (
  echo Repository not connected to remote origin. Please set up remote manually.
)
git commit -m "Auto deploy update - %date% %time%"

REM Try to push, but don't stop if it fails (may not have remote set up yet)
git push origin %GIT_BRANCH% || echo Remote push failed, continuing with deployment...

REM Connect to VPS and deploy
echo 3. Connecting to VPS and deploying...

REM Create directory if it doesn't exist
ssh -i "%SSH_KEY%" %REMOTE_USER%@%REMOTE_SERVER% "mkdir -p %REMOTE_DIR%"

REM Copy files to remote server using SCP
echo 3.1 Copying files to remote server...
scp -i "%SSH_KEY%" -r ./* %REMOTE_USER%@%REMOTE_SERVER%:%REMOTE_DIR%/

REM Create Docker volumes if they don't exist
echo 3.2 Setting up Docker environment...
ssh -i "%SSH_KEY%" %REMOTE_USER%@%REMOTE_SERVER% "cd %REMOTE_DIR% && docker volume create subscription_config && docker volume create subscription_logs"

REM Stop and remove containers, networks, images, and volumes
echo 3.3 Stopping previous containers...
ssh -i "%SSH_KEY%" %REMOTE_USER%@%REMOTE_SERVER% "cd %REMOTE_DIR% && docker-compose down"

REM Start with forced rebuild
echo 3.4 Building and starting Docker containers...
ssh -i "%SSH_KEY%" %REMOTE_USER%@%REMOTE_SERVER% "cd %REMOTE_DIR% && docker-compose up -d --build"

REM Check service status
echo 4. Checking service status...
ssh -i "%SSH_KEY%" %REMOTE_USER%@%REMOTE_SERVER% "cd %REMOTE_DIR% && docker-compose ps"

echo.
echo ===== Subscription Service Deployment completed! =====
echo Press any key to exit...
pause > nul