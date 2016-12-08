param(
    [string]$build="YES",
    [string]$buildType="Debug",
    [string]$clean="YES",
    [string]$installDotnet="YES",
    [string]$restore="YES",
    [string]$root=$PSScriptRoot,
    [string]$runTests="YES",
    [string]$updateCoreFxVersion="NO",
    [string]$failBuildOnTestFailure="YES")

Write-Host ""
Write-Host "============================"
Write-Host "build.ps1"
Write-Host "build: " $build;
Write-Host "buildType: " $buildType;
Write-Host "clean: " $clean;
Write-Host "installDotnet: " $installDotnet;
Write-Host "restore: " $restore;
Write-Host "root: " $root;
Write-Host "runTests: " $runTests;
Write-Host "PSScriptRoot: " $PSScriptRoot;
Write-Host "updateCoreFxVersion: " $updateCoreFxVersion;
Write-Host "failBuildOnTestFailure: " $failBuildOnTestFailure;

[xml]$buildConfiguration = Get-Content $PSScriptRoot\buildConfiguration.xml
$artifactsRoot = "$root\artifacts";
$dotnetArchitecture  = $buildConfiguration.SelectSingleNode("root/dotnetArchitecture").InnerText;
$dotnetChannel = $buildConfiguration.SelectSingleNode("root/dotnetChannel").InnerText;
$dotnetVersion = $buildConfiguration.SelectSingleNode("root/dotnetVersion").InnerText;
$dotnetInstallDir = "$PSScriptRoot\artifacts\dotnet" + $dotnetVersion;
$dotnetexe = "$dotnetInstallDir\dotnet.exe";
$dotnetUrl =  $buildConfiguration.SelectSingleNode("root/dotnetUrl").InnerText;
$coreFxOldVersion = $buildConfiguration.SelectSingleNode("root/coreFxOldVersion").InnerText;
$coreFxNewVersion = $buildConfiguration.SelectSingleNode("root/coreFxNewVersion").InnerText;
$nugetVersion = $buildConfiguration.SelectSingleNode("root/nugetVersion").InnerText;
$rootNode = $buildConfiguration.root

Write-Host ""
Write-Host "============================"
Write-Host "artifactsRoot: " $artifactsRoot;
Write-Host "dotnetArchitecture: " $dotnetArchitecture;
Write-Host "dotnetChannel: " $dotnetChannel;
Write-Host "dotnetInstallDir: " $dotnetInstallDir;
Write-Host "dotnetVersion: " $dotnetVersion;
Write-Host "dotnetexe: " $dotnetexe;
Write-Host "coreFxOldVersion: " $coreFxOldVersion;
Write-Host "coreFxNewVersion: " $coreFxNewVersion;
Write-Host "nugetVersion: " $nugetVersion;

$ErrorActionPreference = "Stop"

function SetCoreFxVersion([string]$fileName, [string]$oldVersion, [string]$newVersion)
{
    Write-Host ""
    Write-Host "============================"
    Write-Host ">>> SetCoreFxVersion: " $fileName ", " $oldVersion ", " $newVersion

    $content = Get-Content -Path $fileName -raw;
    $newContent = $content -replace $oldVersion, $newVersion;
    Set-Content $fileName $newContent;

    Write-Host "============================"
}

if ($clean)
{
    Write-Host ""
    Write-Host "============================"
    Write-Host "Clean"
    Write-Host ""

    $projects = $buildConfiguration.SelectNodes("root/projects/src/project");
    foreach($project in $projects) {
        $name = $project.name;
        if (Test-Path("$root\src\$name\bin"))
        {
            Write-Host ">>> Remove-Item -Recurse -Force $root\src\$name\bin"
            Remove-Item  -Recurse -Force $root\src\$name\bin
        }

        if (Test-Path("$root\src\$name\obj"))
        {
            Write-Host ">>> Remove-Item -Recurse -Force $root\src\$name\obj"
            Remove-Item  -Recurse -Force $root\src\$name\obj
        }
    }

    $testProjects = $buildConfiguration.SelectNodes("root/projects/test/project")
    foreach ($testProject in $testProjects) {
        $name = $testProject.name;
        if (Test-Path("$root\test\$name\bin"))
        {
            Write-Host ">>> Remove-Item -Recurse -Force $root\test\$name\bin"
            Remove-Item  -Recurse -Force $root\test\$name\bin
        }

        if (Test-Path("$root\test\$name\obj"))
        {
            Write-Host ">>> Remove-Item -Recurse -Force $root\test\$name\obj"
            Remove-Item  -Recurse -Force $root\test\$name\obj
        }
    }

    if (Test-Path $artifactsRoot)
    {
        Write-Host ">>> Remove-Item -Recurse -Force $artifactsRoot"
        Remove-Item  -Recurse -Force $artifactsRoot
    }

    if (Test-Path $dotnetInstallDir)
    {
        Write-Host ">>> Remove-Item -Recurse -Force $dotnetInstallDir"
        Remove-Item  -Recurse -Force $dotnetInstallDir
    }
}

if (!(Test-Path $artifactsRoot))
{
    Write-Host ">>> mkdir $artifactsRoot | Out-Null"
    mkdir $artifactsRoot | Out-Null
}

if ($installDotnet -eq "YES")
{
    Write-Host ""
    Write-Host "============================"
    Write-Host "Install dotnet"
    Write-Host "dotnetVersion = $dotnetVersion"
    Write-Host "dotnetLocalInstallFolder = $dotnetInstallDir"
    Write-Host "dotnetexe = $dotnetexe"
    Write-Host ""

    if (!(Test-Path $dotnetInstallDir))
    {
        Write-Host "mkdir $dotnetInstallDir | Out-Null"
        mkdir $dotnetInstallDir | Out-Null
    }

    # download script to install dotnet
    Write-Host "Invoke-WebRequest $dotnetUrl -OutFile $dotnetInstallDir\dotnet-install.ps1"
    Invoke-WebRequest $dotnetUrl -OutFile "$dotnetInstallDir\dotnet-install.ps1"

    & "$dotnetInstallDir\dotnet-install.ps1" -Channel $dotnetChannel -Version $dotnetVersion -Architecture x64 -InstallDir $dotnetInstallDir -Verbose
    if($LASTEXITCODE -ne 0)
    {
        throw "Failed to install dotnet"
    }
}

if ($updateCoreFxVersion -eq "YES")
{
    Write-Host ""
    Write-Host "============================"
    Write-Host "updateCoreFxVersion"
    Write-Host ""

    Write-Host "root = $root"

    foreach($project in $projects) {
        $name = $project.name;
        SetCoreFxVersion "$root\src\$name\project.json" $coreFxOldVersion $coreFxNewVersion;
    }

    $testProjects = $buildConfiguration.SelectNodes("root/projects/test/project")
    foreach ($testProject in $testProjects) {
        $name = $testProject.name;
        SetCoreFxVersion "$root\test\$name\project.json" $coreFxOldVersion $coreFxNewVersion;
    }
}

if ($restore -eq "YES")
{
    Write-Host ""
    Write-Host "============================"
    Write-Host "RestoreAssemblies"
    Write-Host ""

    Write-Host ">>> Start-Process -wait -NoNewWindow $dotnetexe restore"
    Write-Host ""

    Start-Process -wait -NoNewWindow $dotnetexe "restore"
}

if ($build -eq "YES")
{
    Write-Host ""
    Write-Host "============================"
    Write-Host "Build and pack assemblies"
    Write-Host ""

    $rootNode = $buildConfiguration.projects
    $projects = $buildConfiguration.SelectNodes("root/projects/src/project");
    foreach($project in $projects) {
        $name = $project.name;
        if (Test-Path("$artifactsRoot\build\$name\$buildType"))
        {
            Write-Host ">>> Remove-Item -Recurse -Force $artifactsRoot\build\$name\$buildType (artifacts)"
            Remove-Item -Recurse -Force $artifactsRoot\build\$name\$buildType
        }

        if (Test-Path("$root\src\$name\bin\$buildType"))
        {
            Write-Host ">>> Remove-Item -Recurse -Force $root\src\$name\bin\$buildType (src)"
            Remove-Item -Recurse -Force $root\src\$name\bin\$buildType
        }

        Write-Host ">>> Start-Process -wait -NoNewWindow $dotnetexe pack $root\src\$name -c $buildType -o $root\src\$name\bin\$buildType -s"
        Write-Host ""
        Start-Process -wait -NoNewWindow $dotnetexe "pack $root\src\$name -c $buildType -o $root\src\$name\bin\$buildType -s"
        Write-Host ""
        Write-Host ">>> Copy-Item $root\src\$name\bin\$buildType $artifactsRoot\build\$name\$buildType -Recurse"
        Write-Host ""
        Copy-Item src\$name\bin\$buildType $artifactsRoot\build\$name\$buildType -Recurse
    }
}

if ($runTests -eq "YES")
{
    Write-Host ""
    Write-Host "============================"
    Write-Host "Run Tests"
	Write-Host ""

    $testProjects = $buildConfiguration.SelectNodes("root/projects/test/project")
    foreach ($testProject in $testProjects) {
        $name = $testProject.name;
        Write-Host "";
        Write-Host ">>> Set-Location $root\test\$name"
        Write-Host ">>> Start-Process -wait -passthru -NoNewWindow $dotnetexe test -c $buildType"
        Write-Host ""
        pushd
        Set-Location $root\test\$name
        $p = Start-Process -wait -passthru -NoNewWindow $dotnetexe "test -c $buildType"
        if($p.ExitCode -ne 0)
        {
            if (!$testExitCode)
            {
                $failedTestProjects = "$name"
            }
            else
            {
                $failedTestProjects = "$failedTestProjects, $name"
            }
        }
        $testExitCode = $p.ExitCode + $testExitCode
        popd
    }
    if($testExitCode -ne 0)
    {
        Write-Host ""
        Write-Host "==== Test Failures" -foregroundcolor "DarkRed"
        Write-Host "Failed test projects: $failedTestProjects" -foregroundcolor "DarkRed"
        Write-Host ""
        if($failBuildOnTestFailure -ne "NO")
        {
            throw "Exiting test run."
        }
    }
}

