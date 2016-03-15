setlocal
cls
set dotnethome=%localappdata%\Microsoft\dotnet\cli\bin
for %%* in (.) do set project=%%~nx*
set root=%~dp0%
set xunit-root=%root%..\..\.build\xunit.runner.console\2.1.0\tools
%dotnethome%\dotnet.exe build --configuration Debug
%dotnethome%\dotnet.exe publish --configuration Debug --framework net451  --output obj\testPublish-net451
%xunit-root%\xunit.console.exe %root%obj\testPublish-net451\%project%.dll
endlocal
