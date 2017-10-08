param(
    [string]$build="YES",
    [string]$buildType="Debug",
    [string]$dotnetDir="c:\Program Files\dotnet",
    [string]$clean="YES",
    [string]$restore="YES",
    [string]$root=$PSScriptRoot,
    [string]$runTests="YES",
    [string]$failBuildOnTest="YES",
    [string]$pack="YES",
    [string]$updateAssemblyInfo="YES",
    [string]$slnFile="wilson.sln")

################################################# Functions ############################################################

function WriteSectionHeader($sectionName)
{
    Write-Host ""
    Write-Host "============================"
    Write-Host $sectionName
    Write-Host ""
}

function WriteSectionFooter($sectionName)
{
    Write-Host ""
    Write-Host $sectionName
    Write-Host "============================"
    Write-Host ""
}

function RemoveFolder($folder)
{
    if (Test-Path($folder))
    {
        Write-Host ">>> Remove-Item -Recurse -Force $folder"
        Remove-Item  -Recurse -Force $folder
    }
}

function CreateFolder($path)
{
    if (!(Test-Path $path))
    {
        Write-Host ">>> mkdir $path | Out-Null"
        mkdir $path | Out-Null
    }
}

################################################# Functions ############################################################

WriteSectionHeader("build.ps1 - parameters");
Write-Host "build:              " $build;
Write-Host "buildType:          " $buildType;
Write-Host "dotnetDir:          " $dotnetDir
Write-Host "clean:              " $clean;
Write-Host "restore:            " $restore;
Write-Host "root:               " $root;
Write-Host "runTests:           " $runTests;
Write-Host "failBuildOnTest:    " $failBuildOnTest;
Write-Host "pack:               " $pack;
Write-Host "updateAssemblyInfo: " $updateAssemblyInfo
Write-Host "slnFile:            " $slnFile;
WriteSectionFooter("End build.ps1 - parameters");


[xml]$buildConfiguration = Get-Content $PSScriptRoot\buildConfiguration.xml
$artifactsRoot = "$root\artifacts";
$dotnetexe = "$dotnetDir\dotnet.exe";
$nugetVersion = $buildConfiguration.SelectSingleNode("root/nugetVersion").InnerText;
$releaseVersion = [string]$buildConfiguration.SelectSingleNode("root/release").InnerText;
$nugetPreview = $buildConfiguration.SelectSingleNode("root/nugetPreview").InnerText;
$rootNode = $buildConfiguration.root

WriteSectionHeader("Environment");
$startTime = Get-Date
Write-Host "Start Time:     " $startTime
Write-Host "PSScriptRoot:   " $PSScriptRoot;
Write-Host "artifactsRoot:  " $artifactsRoot;
Write-Host "dotnetexe:      " $dotnetexe;
Write-Host "nugetVersion:   " $nugetVersion;
Write-Host "releaseVersion: " $releaseVersion;
Write-Host "nugetPreview:   " $nugetPreview;
WriteSectionFooter("End Environment");

$ErrorActionPreference = "Stop"

if ($clean -eq "YES")
{
    WriteSectionHeader("Clean");

    $projects = $buildConfiguration.SelectNodes("root/projects/src/project");
    foreach($project in $projects) {
        $name = $project.name;
        RemoveFolder("$root\src\$name\bin");
        RemoveFolder("$root\src\$name\obj");
    }

    $testProjects = $buildConfiguration.SelectNodes("root/projects/test/project")
    foreach ($testProject in $testProjects) {
        $name = $testProject.name;
        RemoveFolder("$root\test\$name\bin");
        RemoveFolder("$root\test\$name\obj");
    }

    RemoveFolder($artifactsRoot);

    WriteSectionFooter("End Clean");
}

if ($build -eq "YES")
{
    WriteSectionHeader("Build");
    CreateFolder($artifactsRoot);

    $date = Get-Date
    $dateTimeStamp = ($date.ToString("yy")-13).ToString() + $date.ToString("MMddHHmmss")
    $versionProps = Get-Content ($PSScriptRoot + "/build/version.props");
    Set-Content "build\dynamicVersion.props" ($versionProps -replace $nugetPreview, ($nugetPreview + "-" + $dateTimeStamp));

    if ($updateAssemblyInfo -eq "YES")
    {
        $projects = $buildConfiguration.SelectNodes("root/projects/src/project");
        $additionFileInfo = $releaseVersion + "." + $dateTimeStamp + "." + (git rev-parse HEAD);
        $dateTimeStamp = ($date.ToString("yy")-13).ToString() + $date.ToString("MMdd");
        $fileVersion = $releaseVersion + "." + $dateTimeStamp;
        foreach($project in $projects)
        {
            $name = $project.name;
            $assemblyInformationalRegex = "AssemblyInformationalVersion(.*)"
            $assemblyInformationalVersion = "AssemblyInformationalVersion(""$additionFileInfo"")]"
            $assemblyFileVersionRegex = "AssemblyFileVersion(.*)"
            $assemblyFileVersion = "AssemblyFileVersion(""$fileVersion"")]"
            Write-Host "assemblyInformationalVersion: "  $assemblyInformationalVersion
            Write-Host "assemblyFileVersion: " $assemblyFileVersion

            $assemblyInfoPath = "$root\src\$name\properties\assemblyinfo.cs";
            $content = Get-Content $assemblyInfoPath;
            $content = $content -replace $assemblyInformationalRegex, $assemblyInformationalVersion;
            $content = $content -replace $assemblyFileVersionRegex, $assemblyFileVersion;
            Set-Content $assemblyInfoPath $content
        }
    }

    Write-Host ">>> Start-Process -wait -NoNewWindow $dotnetexe 'restore' $root\$slnFile"
    Start-Process -wait -NoNewWindow $dotnetexe "restore $root\$slnFile"
    Write-Host ">>> Start-Process -wait -NoNewWindow $dotnetexe 'build' $root\$slnFile"
    Start-Process -wait -NoNewWindow $dotnetexe "build $root\$slnFile"

    WriteSectionFooter("End Build");
}

if ($pack -eq "YES")
{
    WriteSectionHeader("Pack");
    CreateFolder($artifactsRoot);

    foreach($project in $buildConfiguration.SelectNodes("root/projects/src/project"))
    {
        $name = $project.name;
        Write-Host ">>> Start-Process -wait -NoNewWindow $dotnetexe 'pack' --no-build $root\src\$name -c $buildType -o $artifactsRoot -s"
        Start-Process -wait -NoNewWindow $dotnetexe "pack $root\src\$name\$name.csproj --no-build -c $buildType -o $artifactsRoot -s"
    }

    WriteSectionFooter("End Pack");
}

if ($runTests -eq "YES")
{

    $testProjects = $buildConfiguration.SelectNodes("root/projects/test/project")
    foreach ($testProject in $testProjects)
    {
        if ($testProject.test -eq "yes")
        {
            $name = $testProject.name;
            WriteSectionHeader("Test - " + $name);

            Write-Host ">>> Set-Location $root\test\$name"
            pushd
            Set-Location $root\test\$name
            if ($build -ne "YES")
            {
                Write-Host ">>> Start-Process -wait -NoNewWindow $dotnetexe 'restore' $name.csproj"
                Start-Process -wait -NoNewWindow $dotnetexe "restore $name.csproj"
                Write-Host ">>> Start-Process -wait -passthru -NoNewWindow $dotnetexe 'test $name.csproj' -c $buildType"
                $p = Start-Process -wait -passthru -NoNewWindow $dotnetexe "test $name.csproj -c $buildType"
            }
            else
            {
                Write-Host ">>> Start-Process -wait -passthru -NoNewWindow $dotnetexe 'test $name.csproj' --no-build -c $buildType"
                $p = Start-Process -wait -passthru -NoNewWindow $dotnetexe "test $name.csproj --no-build -c $buildType"
            }

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

            WriteSectionFooter("End Test - " + $name);
        }
    }

    if($testExitCode -ne 0)
    {
        WriteSectionHeader("==== Test Failures ====");
        Write-Host "Failed test projects: $failedTestProjects" -foregroundcolor "DarkRed"
        WriteSectionFooter("==== End Test Failures ====");
        if($failBuildOnTest -ne "NO")
        {
            throw "Exiting test run."
        }
    }
}

Write-Host "============================"
Write-Host ""
$time = Get-Date
Write-Host "Start Time:    " ($startTime);
Write-Host "End Time:      " ($time);
Write-Host "Time to build: " ($time - $startTime);
Write-Host ""
Write-Host "============================";
