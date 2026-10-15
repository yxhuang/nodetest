@echo off
setlocal
if defined NODETEST_DISTRO (
    wsl.exe -d "%NODETEST_DISTRO%" -e bash -lc "exec nodetest --ask-label \"$@\"" nodetest %*
) else (
    wsl.exe -e bash -lc "exec nodetest --ask-label \"$@\"" nodetest %*
)
set "NODETEST_EXIT=%ERRORLEVEL%"
pause
exit /b %NODETEST_EXIT%
