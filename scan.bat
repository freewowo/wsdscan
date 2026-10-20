@echo off
chcp 65001 >nul
REM ------------------------------------------------------------------
REM  WSD Scan 命令行快捷方式
REM  用法:  scan.bat [打印机IP] [wsdscan.py 的其他参数...]
REM  例:    scan.bat 192.168.1.100 --dpi 300 --format pdf --out .\scan.pdf
REM ------------------------------------------------------------------
setlocal

set "HOST=192.168.1.100"
if not "%~1"=="" set "HOST=%~1"

REM 依次尝试: PATH 里的 python、py 启动器、常见安装路径
set "PY=python"
%PY% --version >nul 2>&1
if errorlevel 1 set "PY=py"
%PY% --version >nul 2>&1
if errorlevel 1 (
    for %%P in (
        "%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
        "%LOCALAPPDATA%\Programs\Python\Python311\python.exe"
        "%LOCALAPPDATA%\Programs\Python\Python310\python.exe"
        "C:\Python312\python.exe"
        "C:\Python311\python.exe"
        "C:\Python310\python.exe"
    ) do (
        if exist %%P set "PY=%%~P"
    )
)
%PY% --version >nul 2>&1
if errorlevel 1 (
    echo [错误] 找不到 Python。请先安装 Python 3，或改本脚本里的 PY。
    pause
    exit /b 1
)

echo ============================================
echo  WSD Scan  -  printer %HOST%
echo ============================================
%PY% "%~dp0wsdscan.py" --host %HOST% %2 %3 %4 %5 %6 %7 %8
echo.
pause
