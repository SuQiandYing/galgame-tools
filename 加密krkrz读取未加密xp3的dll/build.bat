@echo off
chcp 65001 >nul
set "OUTPUT=version.dll"

:: 自动定位 vcvars32.bat
set "VS_WHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
for /f "usebackq tokens=*" %%i in (`"%VS_WHERE%" -latest -property installationPath`) do (
    set "VS_INSTALL_PATH=%%i"
)
set "VCVARS_PATH=%VS_INSTALL_PATH%\VC\Auxiliary\Build\vcvars32.bat"

if not exist "%VCVARS_PATH%" (
    echo [错误] 找不到 vcvars32.bat，请确认 VS 安装路径。
    pause
    exit /b
)

call "%VCVARS_PATH%"

echo [开始编译] %OUTPUT%...

:: --- 修正后的编译指令 ---
:: /std:c++20         -> 解决 C7555 错误 (支持 .charset 语法)
:: /D "FASTCALL=__fastcall" -> 解决 C2146 错误 (告诉编译器 FASTCALL 的含义)
:: /W3 /O2 /MT /D "USECOMPAT" -> 常规优化与静态链接

cl.exe /LD /Fe%OUTPUT% /O2 /MT /std:c++20 /D "USECOMPAT" /D "FASTCALL=__fastcall" ^
/I"compat" ^
krkr_hxv4_patch.cpp ^
compat\tp_stub.cpp ^
/link /DEF:compat\winversion_v100.def ^
user32.lib gdi32.lib psapi.lib shell32.lib advapi32.lib

if %errorlevel% equ 0 (
    echo.
    echo [成功] 编译完成！
) else (
    echo.
    echo [失败] 编译出错，请检查上方报错。
)
pause