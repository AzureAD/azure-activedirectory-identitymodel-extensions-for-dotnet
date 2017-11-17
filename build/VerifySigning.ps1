param([string]$root, [string]$buildType="Debug")

if(($root -eq $null) -or ($root -eq [System.String]::Empty))
{
    $root = $PSScriptRoot + "\.."
}

$srcPath = $root + "\src"

Write-Host ">>> Searching for sn.exe..."
$snTools = Get-ChildItem ${env:ProgramFiles(x86)}\sn.exe -recurse -ErrorAction Ignore | Sort-Object LastWriteTime -descending
$snTool = $null
$snToolx64 = $null
foreach ($tool in $snTools)
{
    if ($tool.DirectoryName.Contains("x64") -and ($snToolx64 -eq $null))
    {
        $snToolx64 = $tool
    }
    elseif ((-not $tool.DirectoryName.Contains("x64")) -and ($snTool -eq $null))
    {
        $snTool = $tool
    }

    if (($snTool -ne $null) -and ($snToolx64 -ne $null))
    {
        break
    }
}

if (($snTool -eq $null) -and ($snToolx64 -eq $null))
{
    Write-Host ">>> Can not find strong name tool..."
    exit $LASTEXITCODE
}

Write-Host ">>> Searching for signtool.exe..."
$signTools = Get-ChildItem ${env:ProgramFiles(x86)}\signtool.exe -recurse -ErrorAction Ignore | Sort-Object LastWriteTime -descending
$signTool = $null
foreach ($tool in $signTools)
{
    if ($tool.DirectoryName.Contains("x64"))
    {
        $signTool = $tool
        break
    }
}

if ($signTool -eq $null)
{
    Write-Host ">>> Can not find signtool.exe..."
    exit $LASTEXITCODE
}

Write-Host "Verify Signing..."

$snParams = @("-vf", "")
$signParams = @("verify", "/pa", "")

[xml]$buildConfiguration = Get-Content $root\buildConfiguration.xml
$projects = $buildConfiguration.SelectNodes("root/projects/src/project")
$runtimes = $buildConfiguration.root.runtimes.Split(",")
$exitCode = 0

foreach ($project in $projects)
{
    foreach ($runtime in $runtimes)
    {
        $name = $project.name
        $file = Get-ChildItem $srcPath\$name\bin\$buildType\$runtime\$name.dll 2>&1
        if ( $? )
        {
            $snParams[1] = $file
            $unSigned = $false
            if ($snTool -ne $null)
            {
                $x = & "$snTool" $snParams 2>&1
                if (-not $?)
                {
                    $unSigned = $true
                    $exitCode += $LASTEXITCODE
                }
            }
            if ($snToolx64 -ne $null)
            {
                $x = & "$snToolx64" $snParams 2>&1
                if (-not $?)
                {
                    $unSigned = $true
                    $exitCode += $LASTEXITCODE
                }
            }

            if ($unSigned)
            {
                Write-Host "$file is not correctly strong-named signed."
            }

            $signParams[2] = $file.Name
            $x = & "$signTool" $signParams 2>&1
            if (-not $?)
            {
                Write-Host "$file is not Authentication signed."
            }
        }
    }
}

exit $exitCode