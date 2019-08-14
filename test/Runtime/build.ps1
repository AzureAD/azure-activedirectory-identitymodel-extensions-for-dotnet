param(
    [string]$buildType="release",
    [string]$msbuildDir="C:\Program Files (x86)\Microsoft Visual Studio\2017\Enterprise\MSBuild\15.0\Bin",
    [string]$root=$PSScriptRoot)

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

function CreateFolder($folder)
{
    RemoveFolder($folder)
    Write-Host ">>> mkdir $folder | Out-Null"
    mkdir $folder | Out-Null
}

################################################# Functions ############################################################

WriteSectionHeader("build.ps1 - parameters");
Write-Host "buildType:                  " $buildType;
Write-Host "root:                       " $root;
Write-Host "msbuildDir:                 " $msbuildDir;

WriteSectionFooter("End build.ps1 - parameters");

[xml]$buildConfiguration = Get-Content $PSScriptRoot\buildConfiguration.xml
$artifactsRoot = "$root\artifacts";
$msbuildexe = "$msbuildDir\msbuild.exe";

WriteSectionHeader("Environment");
$startTime = Get-Date
Write-Host "Start Time:     " $startTime
Write-Host "PSScriptRoot:   " $PSScriptRoot;
Write-Host "artifactsRoot:  " $artifactsRoot;
Write-Host "msbuildexe:     " $msbuildexe;
WriteSectionFooter("End Environment");

$ErrorActionPreference = "Stop"

WriteSectionHeader("CreateArtifactsRoot");
CreateFolder($artifactsRoot);

WriteSectionHeader("Build");
foreach($project in $buildConfiguration.SelectNodes("root/perf/project"))
{    
    $name = $project.name;
    Write-Host "project.name: " $name
    Write-Host "======================"
    Write-Host ""
    foreach($version in $buildConfiguration.SelectNodes("root/releases/version"))
    {   
        $assemblyVersion = $version.value
        $source = "perf\$name"
        $target = "src\perf\$name\$assemblyVersion"
        Write-Host "Version: " $version.value
        Write-Host "source: " $source
        Write-Host "target: " $target

        RemoveFolder($target)
        $buildPropsPath = "$root\build\build.props"
        $buildProps = Get-Content $buildPropsPath
        $updatedBuildProps = $buildProps -replace "x.y.z", $version.value
        $updatedBuildProps = $updatedBuildProps -replace "root.folder", $root
        $updatedBuildPropsPath = "$target\build.props"

        Write-Host "updatedBuildProps: " $updatedBuildProps
        Write-Host "updatedBuildPropsPath: " $updatedBuildPropsPath
        Copy-Item -Path "perf\$name" -Destination "src\perf\$name\$assemblyVersion" -Recurse
        New-Item -Path "$updatedBuildPropsPath" -Value "$updatedBuildProps" -Force
        Start-Process -wait -PassThru -NoNewWindow $msbuildexe "/restore:True /p:Configuration=$buildType  /p:UseSharedCompilation=false /nr:false /verbosity:m  /p:OutputPath=$artifactsRoot\perf\$name\$assemblyVersion $target\$name.csproj"
    }
}

WriteSectionFooter("End Build");

WriteSectionHeader("Run Tests");

foreach($project in $buildConfiguration.SelectNodes("root/perf/project"))
{
    $name = $project.name;
    $loops = [int]$project.loops;
    $iterations = [int]$project.iterations;
    foreach($version in $buildConfiguration.SelectNodes("root/releases/version"))
    {
        $assemblyVersion = $version.value
        $folder = "$artifactsRoot\perf\$name\$assemblyVersion\"
        $target = "$name.$assemblyVersion.exe"
        WriteSectionHeader("$folder$target -i $iterations -l $loops")
        pushd
        Set-Location $folder
        Start-Process -wait -PassThru -NoNewWindow $folder$target "-i $iterations -l $loops"
        popd
        WriteSectionFooter("$folder$target -i $iterations -l $loops");
    }
}

WriteSectionFooter("End Run Tests");

Write-Host "============================"
Write-Host ""
$time = Get-Date
Write-Host "Start Time:    " ($startTime);
Write-Host "End Time:      " ($time);
Write-Host "Time to build: " ($time - $startTime);
Write-Host ""
Write-Host "============================";
