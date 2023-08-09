#!/bin/bash
set -euo pipefail

scriptroot=$(cd -P "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

packageType=${1:-preview}

date=$(date '+%y%m%d%H%M%S')
# Formats the date by replacing the 4-digit year with a 2-digit value and then subtract 19
dateTimeStamp=$(echo $((10#${date:0:2}-19)))${date:2}

buildConfiguration=$(cat $PWD/buildConfiguration.xml)
commitSha=$(git rev-parse HEAD)

assemblyVersion=$(echo $buildConfiguration | xmllint --xpath 'string(/root/assemblyVersion)' -)
assemblyFileVersion="$assemblyVersion.${dateTimeStamp::-6}" # Trim minutes/seconds
assemblyInformationalVersion="$assemblyVersion.$dateTimeStamp.$commitSha"

echo "assemblyVersion: $assemblyVersion"
echo "assemblyFileVersion: $assemblyFileVersion"
echo "assemblyInformationalVersion: $assemblyInformationalVersion"

nugetSuffix=$(xmllint --xpath "string(/root/nugetSuffix)" buildConfiguration.xml)
if [ "$packageType" = "release" ]
then
    versionSuffix=""
else
    versionSuffix="$nugetSuffix-$dateTimeStamp"
fi

echo "nugetSuffix: $nugetSuffix"

versionPath="$PWD/build/version.props"
version=$(cat $versionPath)
version=$(echo "$version" | sed "s|<VersionPrefix>.*</VersionPrefix>|<VersionPrefix>$assemblyVersion</VersionPrefix>|")
version=$(echo "$version" | sed "s|<VersionSuffix>.*</VersionSuffix>|<VersionSuffix>$versionSuffix</VersionSuffix>|")
echo "$version" > $versionPath

projects=$(xmllint --xpath "/root/projects/src/project/@name" buildConfiguration.xml | sed 's/^[^"]*"\([^"]*\)".*/\1/')

for project in $projects; do
    name="$project"
    assemblyInfoPath="$PWD/src/$name/Properties/AssemblyInfo.cs"
    echo "assemblyInfoPath: $assemblyInfoPath"

    assemblyInfo=$(cat $assemblyInfoPath)
    assemblyInfo=$(echo "$assemblyInfo" | sed "s|AssemblyVersion.*|AssemblyVersion(\"$assemblyVersion\")]|")
    assemblyInfo=$(echo "$assemblyInfo" | sed "s|AssemblyFileVersion.*|AssemblyFileVersion(\"$assemblyFileVersion\")]|")
    assemblyInfo=$(echo "$assemblyInfo" | sed "s|AssemblyInformationalVersion.*|AssemblyInformationalVersion(\"$assemblyInformationalVersion\")]|")
    echo "$assemblyInfo" > $assemblyInfoPath
done
