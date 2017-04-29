param(
    [string]$build="YES",
    [string]$buildType="Debug",
    [string]$dotnetDir="c:\dotnet.1.0.3",
    [string]$clean="YES",
    [string]$restore="YES",
    [string]$root=$PSScriptRoot,
    [string]$runTests="YES",
    [string]$failBuildOnTestFailure="YES",
    [string]$pack="YES",
    [string]$addAdditionalFileInfo="NO")

Write-Host ""
Write-Host "============================"
Write-Host "build.ps1"
Write-Host "build: " $build;
Write-Host "buildType: " $buildType;
Write-Host "clean: " $clean;
Write-Host "restore: " $restore;
Write-Host "root: " $root;
Write-Host "runTests: " $runTests;
Write-Host "PSScriptRoot: " $PSScriptRoot;
Write-Host "failBuildOnTestFailure: " $failBuildOnTestFailure;
Write-Host "dotnetDir: " $dotnetDir

[xml]$buildConfiguration = Get-Content $PSScriptRoot\buildConfiguration.xml
$artifactsRoot = "$root\artifacts";
$dotnetexe = "$dotnetDir\dotnet.exe";
$nugetVersion = $buildConfiguration.SelectSingleNode("root/nugetVersion").InnerText;
$rootNode = $buildConfiguration.root

Write-Host ""
Write-Host "============================"
Write-Host "artifactsRoot: " $artifactsRoot;
Write-Host "dotnetexe: " $dotnetexe;
Write-Host "nugetVersion: " $nugetVersion;

$ErrorActionPreference = "Stop"

if ($clean -eq "YES")
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
        Write-Host ">>> Remove-Item -Recurse -Force $buildRoot"
        Remove-Item  -Recurse -Force $artifactsRoot
    }
}

if ($build -eq "YES")
{
    Write-Host ""
    Write-Host "============================"
    Write-Host "Build and pack assemblies"
    Write-Host ""

    if (!(Test-Path $artifactsRoot))
    {
        Write-Host ">>> mkdir $artifactsRoot | Out-Null"
        mkdir $artifactsRoot | Out-Null
    }

    $date = Get-Date
    if ($addAdditionalFileInfo -eq "YES")
    {
        $dateTimeStamp = ($date.ToString("yy")-13).ToString() + $date.ToString("MMddHHmmss");
        $additionFileInfo = "5.2.0." + $dateTimeStamp + "." + (git rev-parse HEAD);
        $dateTimeStamp = ($date.ToString("yy")-13).ToString() + $date.ToString("MMdd");
        $fileVersion = "5.2.0." + $dateTimeStamp;
    }

    $dateTimeStamp = ($date.ToString("yy")-13).ToString() + $date.ToString("MMddHHmm")
    $postfix = "." + $dateTimeStamp;
    $versionPropsFile = $PSScriptRoot + "/build/version.props";
    $versionProps = Get-Content $versionPropsFile
    $newVersion = "5.2.0" + $postfix;
    $newVersionProps = $versionProps -replace "5.2.0", $newVersion;
    Set-Content "build\dynamicVersion.props" $newVersionProps;
    $rootNode = $buildConfiguration.projects
    $projects = $buildConfiguration.SelectNodes("root/projects/src/project");
    foreach($project in $projects)
    {
        $name = $project.name;
        if ($addAdditionalFileInfo -eq "YES")
        {
            $assemblyInfoPath = "$root\src\$name\properties\assemblyinfo.cs";
            $content = Get-Content $assemblyInfoPath;
            $content = $content + "[assembly: AssemblyInformationalVersion(""$additionFileInfo"")]";
            $content = $content + "[assembly: AssemblyFileVersion(""$fileVersion"")]";
            Set-Content $assemblyInfoPath $content
        }

        Write-Host "======================"
        Write-Host ">>> Start-Process -wait -NoNewWindow $dotnetexe 'restore' $root\src\$name\$name.csproj"
        Write-Host ""
        Start-Process -wait -NoNewWindow $dotnetexe "restore $root\src\$name\$name.csproj"
        Write-Host "======================"
        Write-Host ">>> Start-Process -wait -NoNewWindow $dotnetexe 'build' $root\src\$name\$name.csproj"
        Write-Host ""
        Start-Process -wait -NoNewWindow $dotnetexe "build $root\src\$name\$name.csproj"
    }
}

if ($pack -eq "YES")
{
    Write-Host ""
    Write-Host "============================"
    Write-Host "Pack assemblies"
    Write-Host ""

    if (!(Test-Path $artifactsRoot))
    {
        Write-Host ">>> mkdir $artifactsRoot | Out-Null"
        mkdir $artifactsRoot | Out-Null
    }

    $projects = $buildConfiguration.SelectNodes("root/projects/src/project");
    foreach($project in $projects) {
        $name = $project.name;
        Write-Host "======================"
        Write-Host ">>> Start-Process -wait -NoNewWindow $dotnetexe 'pack' --no-build $root\src\$name -c $buildType -o $artifactsRoot -s"
        Write-Host ""
        Start-Process -wait -NoNewWindow $dotnetexe "pack $root\src\$name\$name.csproj --no-build -c $buildType -o $artifactsRoot -s"
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
        pushd
        Set-Location $root\test\$name
        Write-Host "======================"
        Write-Host ">>> Start-Process -wait -NoNewWindow $dotnetexe 'restore' $name.csproj"
        Write-Host ""
        Start-Process -wait -NoNewWindow $dotnetexe "restore $name.csproj"
        Write-Host "======================"
        Write-Host ">>> Start-Process -wait -passthru -NoNewWindow $dotnetexe 'test' -c $buildType"
        Write-Host ""
        $p = Start-Process -wait -passthru -NoNewWindow $dotnetexe "test $name.csproj -c $buildType"
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

