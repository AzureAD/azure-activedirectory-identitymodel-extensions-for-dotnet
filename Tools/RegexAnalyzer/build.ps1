param(
    [string]$build="YES",
    [string]$buildType="Debug",
    [string]$dotnetDir="c:\Program Files\dotnet",
    [string]$msbuildexe="C:\Program Files (x86)\Microsoft Visual Studio\2017\Enterprise\MSBuild\15.0\Bin\MSBuild.exe",
    [string]$clean="YES",
    [string]$restore="YES",
    [string]$root=$PSScriptRoot,
    [string]$wilsonRoot = (get-item $PSScriptRoot).parent.parent.FullName,
    [string]$runTests="YES",
    [string]$failBuildOnTest="YES",
    [string]$updateAssemblyInfo="YES",
    [string]$slnFile="RegexAnalyzer.sln")

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
Write-Host "msbuildDir:         " $msbuildDir;
Write-Host "clean:              " $clean;
Write-Host "restore:            " $restore;
Write-Host "root:               " $root;
Write-Host "wilsonRoot:         " $wilsonRoot;
Write-Host "runTests:           " $runTests;
Write-Host "failBuildOnTest:    " $failBuildOnTest;
Write-Host "updateAssemblyInfo: " $updateAssemblyInfo
Write-Host "slnFile:            " $slnFile;
WriteSectionFooter("End build.ps1 - parameters");


[xml]$buildConfiguration = Get-Content $wilsonRoot\buildConfiguration.xml
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
Write-Host "msbuildexe:     " $msbuildexe;
Write-Host "nugetVersion:   " $nugetVersion;
Write-Host "releaseVersion: " $releaseVersion;
Write-Host "nugetPreview:   " $nugetPreview;
WriteSectionFooter("End Environment");

$ErrorActionPreference = "Stop"

if ($clean -eq "YES")
{
    WriteSectionHeader("Clean");

    $tools = $buildConfiguration.SelectNodes("root/tools/tool")
    foreach ($tool in $tools) {
        $toolName = $tool.Name;
        RemoveFolder("$root\$toolName\$toolName\bin");
        RemoveFolder("$root\$toolName\$toolName\obj");

        $toolTests= $buildConfiguration.SelectNodes("root/tools/tool[@name='$toolName']/test")
        foreach ($test in $toolTests) {
            $name = $test.name;
            RemoveFolder("$root\$toolName\$name\bin");
            RemoveFolder("$root\$toolName\$name\obj");
        }
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
    $versionProps = Get-Content ($wilsonRoot + "/build/version.props");
    Set-Content ($wilsonRoot + "\build\dynamicVersion.props") ($versionProps -replace $nugetPreview, ($nugetPreview + "-" + $dateTimeStamp));

    if ($updateAssemblyInfo -eq "YES")
    {
        $projects = $buildConfiguration.SelectNodes("root/tools/tool[@name='RegexAnalyzer']/project");
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

            $assemblyInfoPath = "$root\RegexAnalyzer\$name\properties\assemblyinfo.cs";
            $content = Get-Content $assemblyInfoPath;
            $content = $content -replace $assemblyInformationalRegex, $assemblyInformationalVersion;
            $content = $content -replace $assemblyFileVersionRegex, $assemblyFileVersion;
            Set-Content $assemblyInfoPath $content
        }
    }
    
    Write-Host ">>>" + $msbuildexe + "$root/RegexAnalyzer.sln  /t:restore"
    & $msbuildexe "RegexAnalyzer.sln" "/t:restore"
    Write-Host ">>>" + $msbuildexe + "$root/RegexAnalyzer.sln  /t:build"
    & $msbuildexe "RegexAnalyzer.sln" "/t:build"

    WriteSectionFooter("End Build");
}

if ($runTests -eq "YES")
{
    WriteSectionHeader("Test");
    foreach($tool in $buildConfiguration.SelectNodes("root/tools/tool")) 
    {
        $toolName = $tool.Name;
        $testProjects = $buildConfiguration.SelectNodes("root/tools/tool[@name='$toolName']/test")
        foreach ($testProject in $testProjects)
        {
            if ($testProject.test -eq "yes")
            {
                $name = $testProject.name;
                WriteSectionHeader("Test - " + $name);

                Write-Host ">>> Set-Location $root\$tool\$name"
                pushd
                Set-Location $root\$toolName\$name
                if ($build -ne "YES")
                {
                    Write-Host ">>> Start-Process -wait -NoNewWindow $msbuildexe 'restore' $name.csproj"
                    Start-Process -wait -NoNewWindow $dotnetexe"restore $name.csproj"
                    Write-Host ">>> Start-Process -wait -passthru -NoNewWindow $msbuildexe 'test $name.csproj' -c $buildType"
                    $p = Start-Process -wait -passthru -NoNewWindow $dotnetexe "test $name.csproj -c $buildType"
                }
                else
                {
                    Write-Host ">>> Start-Process -wait -passthru -NoNewWindow $msbuildexe 'test $name.csproj' --no-build -c $buildType"
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

    WriteSectionFooter("End Test")
}

Write-Host "============================"
Write-Host ""
$time = Get-Date
Write-Host "Start Time:    " ($startTime);
Write-Host "End Time:      " ($time);
Write-Host "Time to build: " ($time - $startTime);
Write-Host ""
Write-Host "============================";
