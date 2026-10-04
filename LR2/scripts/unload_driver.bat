@echo off
rem unload_driver.bat - выгружает минифильтр PassThrough (ЛР2) из стека.
rem Запускать от имени администратора внутри тестовой виртуальной машины.
net session >nul 2>&1
if errorlevel 1 (
    echo Запустите этот файл от имени администратора.
    exit /b 1
)
fltmc unload PassThrough
if errorlevel 1 (
    echo Не удалось выгрузить драйвер. Возможно, он уже выгружен.
    exit /b 1
)
echo Драйвер PassThrough выгружен.
fltmc filters
