setlocal
cls
set dotnethome=%localappdata%\Microsoft\dotnet
for %%* in (.) do set project=%%~nx*
set root=%~dp0%
set xunit-root=%root%..\..\.build\xunit.runner.console\2.1.0\tools
%dotnethome%\dotnet.exe restore
%dotnethome%\dotnet.exe build --configuration Debug
REM %xunit-root%\xunit.console.exe bin\Debug\net451\win7-x64\%project%.dll
%dotnethome%\dotnet.exe test --no-build --configuration Debug
endlocal
