#!/usr/bin/env bash
set -e
repoFolder="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd $repoFolder

function build {
    folder="src/$1"
    if [ ! -d $folder ]; then
        echo "Specified folder [$folder] does not exist"
        exit 1
    fi
    
    echo "Building $folder"
    pushd $folder
    
    proj=$(ls *.csproj | head -n 1)
    if [ -z "$proj" ]; then 
        echo "No .csproj files found in $folder"
        exit 1
    fi

    # .Netcore doesn't support 4.5.1
    echo "Removing net4.5.1 from target frameworks in $proj"
    sed -i 's/;net451//g' $proj

    # .NetCore doesn't support the 'delaysign' and 'publicsign' options together
    echo "Removing <DelaySign> option from $proj"
    sed -i "/DelaySign/d" $proj
    
    ~/.dotnet/dotnet restore $proj
    ~/.dotnet/dotnet build $proj
    popd
}

koreBuildZip="https://github.com/aspnet/KoreBuild/archive/dev.zip"
if [ ! -z $KOREBUILD_ZIP ]; then
    koreBuildZip=$KOREBUILD_ZIP
fi

buildFolder=".build"
buildFile="$buildFolder/KoreBuild.sh"

if test ! -d $buildFolder; then
    echo "Downloading KoreBuild from $koreBuildZip"

    tempFolder="/tmp/KoreBuild-$(uuidgen)"
    mkdir $tempFolder

    localZipFile="$tempFolder/korebuild.zip"

    retries=6
    until (wget -O $localZipFile $koreBuildZip 2>/dev/null || curl -o $localZipFile --location $koreBuildZip 2>/dev/null)
    do
        echo "Failed to download '$koreBuildZip'"
        if [ "$retries" -le 0 ]; then
            exit 1
        fi
        retries=$((retries - 1))
        echo "Waiting 10 seconds before retrying. Retries left: $retries"
        sleep 10s
    done

    unzip -q -d $tempFolder $localZipFile

    mkdir $buildFolder
    cp -r $tempFolder/**/build/** $buildFolder

    chmod +x $buildFile

    # Cleanup
    if test ! -d $tempFolder; then
        rm -rf $tempFolder
    fi
fi


echo "Migrating projects to new format"
~/.dotnet/dotnet migrate

build Microsoft.IdentityModel.Logging 
build Microsoft.IdentityModel.Tokens
build System.IdentityModel.Tokens.Jwt
build Microsoft.IdentityModel.Protocols.OpenIdConnect
build Microsoft.IdentityModel.Protocols.WsFederation
build Microsoft.IdentityModel.Protocols 
build System.IdentityModel.Tokens.Saml

