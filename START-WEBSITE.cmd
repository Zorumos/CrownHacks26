@echo off
cd /d "%~dp0"
if not exist "node_modules\nodemailer\package.json" (
  call npm install --omit=dev --ignore-scripts
  if errorlevel 1 (
    echo Dependency installation failed. Check your internet connection and try again.
    pause
    exit /b 1
  )
)
node setup.js
start http://localhost:3000
node --env-file-if-exists=.env server.js
pause
