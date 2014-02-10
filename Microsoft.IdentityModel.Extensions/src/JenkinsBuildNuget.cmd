REM as of 10/31/2013, directories are hard coded so it is possible to clobber a job in progress.
REM hence, this job is not automatic.

set ASSEMBLY_NAME=system.identitymodel.tokens.jwt
set CI_PATH=C:\tools\ci-signing
set EXTERNAL_DROP_PATH=\\Scratch2\Scratch\Brentsch\JenkinsBuilds\%JOB_NAME%\%BUILD_ID%.%BUILD_NUMBER%
set JOB_PATH=c:\workspace\workspace\%JOB_NAME%
set NUGET_PATH=%JOB_PATH%\nugget
set NUGET_PACKAGES=%NUGET_PATH%\Packages
set NUGET_PATH_LIBS=%NUGET_PATH%\lib\net45
set SIGNED_PATH=.\signed
set TO_SIGN_PATH=.\tosign

@echo =
@echo ==========================
@echo Creating signing directories
md %TO_SIGN_PATH%
md %SIGNED_PATH%
md %NUGET_PATH%
md %NUGET_PATH_LIBS%
md %NUGET_PACKAGES%

@echo =
@echo ==========================
@echo Cleaning signed and packages directories
del /q %SIGNED_PATH%\*.*
del /q %TO_SIGN_PATH%\*.*
del /q %NUGET_PACKAGES%
REM del /q c:\packages\*.*

@echo =
@echo ==========================
@echo Copying the dll to signing source directory
copy /y %JOB_PATH%\lib\bin\Release\%ASSEMBLY_NAME%.dll %TO_SIGN_PATH%\

@echo =
@echo ==========================
@echo Signing managed desktop library DLLs...
%CI_PATH%\CodeSignUtility\csu.exe /c1=72 /c2=10006 /i=%TO_SIGN_PATH%/ /o=%SIGNED_PATH%/ "/d=JwtSecurityTokenHandler" "/kw=JWT,WIF,NetSDK"

@echo =
@echo ==========================
@echo Copying signed native DLLs and the pdbs to the final drop location...
md .\drop\lib\net45
copy /y %SIGNED_PATH%\%ASSEMBLY_NAME%.dll .\drop\lib\net45
copy /y %JOB_PATH%\lib\bin\Release\%ASSEMBLY_NAME%.pdb .\drop\lib\net45
copy /y %JOB_PATH%\lib\bin\Release\%ASSEMBLY_NAME%.xml .\drop\lib\net45
copy /y %JOB_PATH%\%ASSEMBLY_NAME%.nuspec .\drop

REM copy /y %SIGNED_PATH%\%ASSEMBLY_NAME%.dll %NUGET_PATH_LIBS%
REM copy /y %JOB_PATH%\lib\bin\Release\%ASSEMBLY_NAME%.pdb %NUGET_PATH_LIBS%
REM copy /y %JOB_PATH%\lib\bin\Release\%ASSEMBLY_NAME%.xml %NUGET_PATH_LIBS%
REM copy /y %JOB_PATH%\%ASSEMBLY_NAME%.nuspec %NUGET_PATH%

@echo =
@echo ==========================
@echo Creating NuGet Packages....
md %EXTERNAL_DROP_PATH%\Signed
md %EXTERNAL_DROP_PATH%\ToSign
md %EXTERNAL_DROP_PATH%\Packages
REM %CI_PATH%\utility\NuGet.exe pack .\drop\%ASSEMBLY_NAME%.nuspec -o c:\packages -Symbols
%CI_PATH%\utility\NuGet.exe pack .\drop\%ASSEMBLY_NAME%.nuspec -o %NUGET_PACKAGES% -Symbols

REM copy /y c:\packages\*.* %JOB_PATH%\drop\lib\net45
REM copy /y c:\packages\*.* %EXTERNAL_DROP_PATH%\packages

copy /y %NUGET_PACKAGES%\*.* %JOB_PATH%\drop\lib\net45
copy /y %NUGET_PACKAGES%\*.* %EXTERNAL_DROP_PATH%\packages

copy /y %TO_SIGN_PATH%\*.* %EXTERNAL_DROP_PATH%\ToSign
copy /y %SIGNED_PATH%\*.* %EXTERNAL_DROP_PATH%\Signed
copy /y %JOB_PATH%\lib\bin\Release\%ASSEMBLY_NAME%.pdb %EXTERNAL_DROP_PATH%\Signed
copy /y %JOB_PATH%\lib\bin\Release\%ASSEMBLY_NAME%.xml %EXTERNAL_DROP_PATH%\Signed

@echo =
@echo ==========================
@echo Removing all files and packages ...
del /q %SIGNED_PATH%\*.*
del /q %TO_SIGN_PATH%\*.*
REM del /q c:\packages\*.*
del /q %NUGET_PACKAGES% 

echo ==========================
echo DONE