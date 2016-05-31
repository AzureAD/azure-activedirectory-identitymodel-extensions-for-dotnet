param([string]$build="YES", [string]$buildType="Debug", [string]$installdotnet="YES", [string]$restore="YES", [string]$runtests="YES", [string]$updateCoreFxVersion="YES")

$ErrorActionPreference = "Stop"
& ".build\build.ps1" -build $build -buildType $buildType -installdotnet $installdotnet -restore $restore -root $PSScriptRoot -runtests $runtests -updateCoreFxVersion $updateCoreFxVersion

