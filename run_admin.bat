@echo off
REM Network Guardian - Yönetici panelini başlat
cd /d "%~dp0"
echo [Network Guardian] Yönetici paneli başlatılıyor...
echo.
python -m server.admin_app
pause
