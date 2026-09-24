@echo off
cd /d "%~dp0"

where uv >nul 2>nul
if %errorlevel% equ 0 (
    uv run python main.py %*
    goto :END
)

if exist ".venv\\Scripts\\python.exe" (
    ".venv\\Scripts\\python.exe" main.py %*
    goto :END
)

python main.py %*

:END
echo.
pause
