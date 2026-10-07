@echo off
rem load_driver.bat - включает минифильтр PassThrough (ЛР2) и показывает его место в стеке.
rem Запускать от имени администратора внутри тестовой виртуальной машины.
net session >nul 2>&1
if errorlevel 1 (
    echo Запустите этот файл от имени администратора.
    echo.
    pause
    exit /b 1
)
fltmc load PassThrough
if errorlevel 1 (
    echo Не удалось загрузить драйвер. Проверьте установку INF и подпись (testsigning).
    echo.
    pause
    exit /b 1
)
echo.
echo Фильтры, загруженные в систему:
fltmc filters
echo.
echo Экземпляры фильтра на томах:
fltmc instances
echo.
pause
