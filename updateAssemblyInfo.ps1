param([string]$root=$PSScriptRoot)

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
    Write-Host $sectionName
    Write-Host "End Time:     "  $startTime		
    Write-Host "============================"
    Write-Host ""
}


################################################# Functions ############################################################

WriteSectionHeader("updateAssemblyInfo.ps1");

Write-Host "root:           " $root;
Write-Host "PSScriptRoot:   " $PSScriptRoot;

[xml]$buildConfiguration = Get-Content $PSScriptRoot\buildConfiguration.xml
$releaseVersion = [string]$buildConfiguration.SelectSingleNode("root/release").InnerText;
$nugetPreview = $buildConfiguration.SelectSingleNode("root/nugetPreview").InnerText;
$date = Get-Date
$dateTimeStamp = ($date.ToString("yy")-13).ToString() + $date.ToString("MMddHHmmss")
$projects = $buildConfiguration.SelectNodes("root/projects/src/project");
$additionFileInfo = $releaseVersion + "." + $dateTimeStamp + "." + (git rev-parse HEAD);
$nugetVersion = $dateTimeStamp;
$dateTimeStamp = ($date.ToString("yy")-13).ToString() + $date.ToString("MMdd");
$fileVersion = $releaseVersion + "." + $dateTimeStamp;
$versionProps = Get-Content ($PSScriptRoot + "/build/version.props");
Set-Content "build\dynamicVersion.props" ($versionProps -replace $nugetPreview, ($nugetPreview + "-" + $nugetVersion));

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

WriteSectionFooter("updateAssemblyInfo.ps1");
