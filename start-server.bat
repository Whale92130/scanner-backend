@echo off
cd /d "%~dp0"

if not exist node_modules (
    npm install express openai
)

set "OPENAI_API_KEY=fake_key"

node server.mjs

pause