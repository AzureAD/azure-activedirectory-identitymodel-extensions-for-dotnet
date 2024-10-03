param(
    [string]$buildType="Debug",
    [string]$dotnetDir="c:\Program Files\dotnet",
    [string]$msbuildDir="C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\MSBuild\Current\Bin",
    [string]$root=$PSScriptRoot,
    [string]$runTests="YES",
    [string]$failBuildOnTest="YES",
    [string]$slnFile="wilson.sln"
)

################################################# Functions ############################################################

function WriteSectionHeader($sectionName)
{
    $startTime = Get-Date -DisplayHint Time
    Write-Host ""
    Write-Host "============================"
    Write-Host $sectionName
    Write-Host "Start Time:     "  $startTime
    Write-Host ""
}

function WriteSectionFooter($sectionName)
{
    $startTime = Get-Date -DisplayHint Time
    Write-Host ""
    Write-Host "End Time:     "  $startTime
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

function CreateArtifactsRoot($folder)
{
    RemoveFolder($folder)
    Write-Host ">>> mkdir $folder | Out-Null"
    mkdir $folder | Out-Null
}

################################################# Functions ############################################################

if ($env:VSINSTALLDIR)
{
    if (Test-Path($env:VSINSTALLDIR+"\MSBuild\Current\Bin"))
    {
        $msbuildDir = $env:VSINSTALLDIR+"\MSBuild\Current\Bin";
    }
}

WriteSectionHeader("build.ps1 - parameters");
Write-Host "buildType:                  " $buildType;
Write-Host "dotnetDir:                  " $dotnetDir
Write-Host "root:                       " $root;
Write-Host "runTests:                   " $runTests;
Write-Host "failBuildOnTest:            " $failBuildOnTest;
Write-Host "slnFile:                    " $slnFile;
WriteSectionFooter("End build.ps1 - parameters");

[xml]$buildConfiguration = Get-Content $PSScriptRoot\buildConfiguration.xml
$artifactsRoot = "$root\artifacts";
$dotnetexe = "$dotnetDir\dotnet.exe";
$msbuildexe = "$msbuildDir\msbuild.exe";
$nugetVersion = $buildConfiguration.SelectSingleNode("root/nugetVersion").InnerText;
$releaseVersion = [string]$buildConfiguration.SelectSingleNode("root/release").InnerText;
$nugetPreview = $buildConfiguration.SelectSingleNode("root/nugetPreview").InnerText;

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

 WriteSectionHeader("VerifyResourceUsage.pl");

 Write-Host ">>> Start-Process -Wait -PassThru -NoNewWindow powershell $root\tools\VerifyResourceUsage.ps1"
 $verifyResourceUsageResult = Start-Process -Wait -PassThru -NoNewWindow powershell $root\tools\VerifyResourceUsage.ps1

 if($verifyResourceUsageResult.ExitCode -ne 0)
 {
 	throw "VerifyResourceUsage.ps1 failed."
 }

 WriteSectionFooter("End VerifyResourceUsage.ps1");

WriteSectionHeader("Build");

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

CreateArtifactsRoot($artifactsRoot);

pushd
Set-Location $root
Write-Host ""
Write-Host ">>> Start-Process -wait -NoNewWindow $msbuildexe /restore:True /p:UseSharedCompilation=false /nr:false /verbosity:m /p:Configuration=$buildType $slnFile"
Write-Host ""
Write-Host "msbuildexe: " $msbuildexe
$p = Start-Process -Wait -PassThru -NoNewWindow $msbuildexe "/r:True /p:UseSharedCompilation=false /nr:false /verbosity:m /p:Configuration=$buildType $slnFile"

if($p.ExitCode -ne 0)
{
	throw "Build failed."
}
popd

foreach($project in $buildConfiguration.SelectNodes("root/projects/src/project"))
{
	$name = $project.name;
	Write-Host ">>> Start-Process -Wait -PassThru -NoNewWindow $dotnetexe 'pack' --no-build --no-restore -nodereuse:false -c $buildType -o $artifactsRoot -v m -s $root\src\$name\$name.csproj"
	Start-Process -wait -PassThru -NoNewWindow $dotnetexe "pack --no-build --no-restore -nodereuse:false -c $buildType -o $artifactsRoot -v m -s $root\src\$name\$name.csproj"
}

WriteSectionFooter("End Build");

if ($runTests -eq "YES")
{
    WriteSectionHeader("Run Tests");

    $testProjects = $buildConfiguration.SelectNodes("root/projects/test/project")
    foreach ($testProject in $testProjects)
    {
        if ($testProject.test -eq "YES")
        {
            WriteSectionHeader("Test");

            $name = $testProject.name;
            Write-Host ">>> Set-Location $root\test\$name"
            pushd
            Set-Location $root\test\$name
            Write-Host ">>> Start-Process -Wait -PassThru -NoNewWindow $dotnetexe 'test $name.csproj' --filter category!=nonwindowstests --no-build --no-restore -nodereuse:false -v n -c $buildType"
            $p = Start-Process -Wait -PassThru -NoNewWindow $dotnetexe "test $name.csproj --filter category!=nonwindowstests --no-build --no-restore -nodereuse:false -v n -c $buildType"

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

            WriteSectionFooter("End Test");
        }
    }

    WriteSectionFooter("End Tests");

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
