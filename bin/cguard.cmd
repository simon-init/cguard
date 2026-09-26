@echo off
rem Command line for the cguard plugin on Windows. Put this folder on PATH, or call it by path.
rem Uses the Python launcher when it exists, and python otherwise.
setlocal
set "CLI=%~dp0..\cguard\cli.py"
where py >nul 2>nul
if %errorlevel%==0 (
  py -3 "%CLI%" %*
) else (
  python "%CLI%" %*
)
exit /b %errorlevel%
