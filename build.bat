@echo off
REM -------------------------------------------------------------------
REM  WSD Scan 打包脚本：生成 dist\WsdScan.exe（单文件，含图标）
REM  依赖：Python 3.9+、pyinstaller、pillow
REM    pip install pyinstaller pillow
REM -------------------------------------------------------------------
setlocal
cd /d "%~dp0"

if not exist "wsdscan.ico" (
    echo [ERROR] wsdscan.ico 不存在，请先运行 tools\make_icon.py
    exit /b 1
)

echo [1/3] 清理旧产物...
taskkill /F /IM WsdScan.exe >nul 2>&1
if exist "dist" rmdir /s /q "dist"
if exist "build" rmdir /s /q "build"
if exist "WsdScan.spec" del /q "WsdScan.spec"

echo [2/3] PyInstaller 打包（含图标与内嵌资源）...
python -m PyInstaller --noconfirm --onefile --windowed ^
    --name WsdScan ^
    --icon wsdscan.ico ^
    --add-data "wsdscan.ico;." ^
    --add-data "wsdscan.png;." ^
    --exclude-module numpy ^
    --exclude-module scipy ^
    --exclude-module pandas ^
    --exclude-module matplotlib ^
    --exclude-module pytest ^
    --exclude-module setuptools ^
    --exclude-module pip ^
    --exclude-module PyInstaller ^
    --exclude-module unittest ^
    --exclude-module pydoc ^
    --exclude-module doctest ^
    --exclude-module sqlite3 ^
    --exclude-module xmlrpc ^
    --exclude-module tkinter.test ^
    --exclude-module test ^
    WsdScanGUI.py
if errorlevel 1 (
    echo [ERROR] 打包失败
    exit /b 1
)

echo [3/3] 完成：
if exist "dist\WsdScan.exe" (
    for %%I in ("dist\WsdScan.exe") do echo     dist\WsdScan.exe  %%~zI bytes
) else (
    echo [ERROR] 未找到 dist\WsdScan.exe
    exit /b 1
)

REM 说明：不裁模块的话产物约 29MB，裁剪后约 13.6MB。
REM 裁剪是安全的：本程序只用标准库 + tkinter + 可选 Pillow。
endlocal
