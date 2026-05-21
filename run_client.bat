@echo off
REM Network Guardian - Client tarafının 3 bileşenini ayrı pencerelerde başlatır
REM Kullanım:  run_client.bat 192.168.1.10

cd /d "%~dp0"

if "%~1"=="" (
    echo Kullanim: run_client.bat ^<yonetici_ip^>
    echo Ornek:   run_client.bat 192.168.1.10
    pause
    exit /b 1
)

set SERVER_IP=%~1

echo [Network Guardian] Client baslatiliyor (sunucu: %SERVER_IP%)
echo.

start "Guardian Proxy"  cmd /k mitmdump -s client/proxy_engine.py -p 8080
start "Guardian Agent"  cmd /k python -m client.agent --server %SERVER_IP%
start "Guardian Tray"   cmd /k python -m client.tray_app --server %SERVER_IP%

echo Uc bilesen ayri pencerelerde baslatildi.
echo Sistem proxy'sini etkinlestirmeyi unutmayin:
echo   python -m client.configure_proxy enable
pause
