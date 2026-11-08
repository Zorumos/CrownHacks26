@echo off
cd /d "%~dp0"
node setup.js
start http://localhost:3000
node --env-file-if-exists=.env server.js
pause
